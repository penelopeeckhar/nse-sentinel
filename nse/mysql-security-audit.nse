description = [[
NSE-Sentinel MySQL Security Audit

Performs a safe, protocol-level audit of a MySQL server.
The script analyzes the initial MySQL handshake to identify
potentially weak security characteristics such as:

* Legacy MySQL protocol versions
* Missing TLS/SSL support
* Local infile capability
* Weak or legacy authentication capabilities
* Compression support
* Basic server information disclosure

No credentials, authentication attempts, brute force, or SQL
queries are performed.

Designed for authorized security assessment and laboratory
environments.
]]

author = "Abir Majdi - NSE-Sentinel"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

local mysql = require "mysql"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

portrule = shortport.port_or_service(3306, "mysql")

local function add_finding(findings, name, severity, status, recommendation)
  findings[#findings + 1] = {
    name = name,
    severity = severity,
    status = status,
    recommendation = recommendation
  }
end

local function calculate_score(findings)
  local weights = {
    low = 5,
    medium = 15,
    high = 25,
    critical = 40
  }

  local score = 0

  for _, finding in ipairs(findings) do
    if finding.status == "WEAK" or finding.status == "PRESENT" then
      score = score + (weights[finding.severity] or 0)
    end
  end

  return math.min(score, 100)
end

local function risk_level(score)
  if score >= 80 then
    return "CRITICAL"
  elseif score >= 60 then
    return "HIGH"
  elseif score >= 30 then
    return "MEDIUM"
  elseif score > 0 then
    return "LOW"
  end

  return "INFORMATIONAL"
end

local function capability_list(value, lookup)
  local result = {}

  for name, flag in pairs(lookup) do
    if (value & flag) > 0 then
      result[#result + 1] = name
    end
  end

  table.sort(result)

  return result
end

local function has_capability(value, capability)
  return (value & capability) > 0
end

action = function(host, port)

  local output = stdnse.output_table()
  local findings = {}

  output["Target"] = host.ip
  output["Port"] = port.number

  local socket = nmap.new_socket()

  local status, err = socket:connect(host, port)

  if not status then
    output["MySQL Error"] = err
    return output
  end

  local greeting_status, info = mysql.receiveGreeting(socket)

  socket:close()

  if not greeting_status then
    output["MySQL Error"] = info
    return output
  end

  output["Protocol Version"] = info.proto
  output["MySQL Version"] = info.version
  output["Thread ID"] = info.threadid

  if info.proto ~= 10 then
    add_finding(
      findings,
      "Legacy MySQL Protocol",
      "high",
      "WEAK",
      "Use a modern supported MySQL protocol and upgrade the server."
    )
  end

  if info.capabilities then

    local capabilities =
      capability_list(info.capabilities, mysql.Capabilities)

    if info.extcapabilities then
      local extended =
        capability_list(
          info.extcapabilities,
          mysql.ExtCapabilities
        )

      for _, capability in ipairs(extended) do
        capabilities[#capabilities + 1] =
          capability
      end
    end

    output["Capabilities"] = capabilities

    if has_capability(
      info.capabilities,
      mysql.Capabilities.SwitchToSSLAfterHandshake
    ) then

      output["TLS Support"] = "ADVERTISED"

    else

      output["TLS Support"] = "NOT ADVERTISED"

      add_finding(
        findings,
        "TLS Support Not Advertised",
        "medium",
        "WEAK",
        "Enable TLS for encrypted MySQL client-server communication."
      )

    end

    if has_capability(
      info.capabilities,
      mysql.Capabilities.SupportsLoadDataLocal
    ) then

      output["LOAD DATA LOCAL"] = "SUPPORTED"

      add_finding(
        findings,
        "LOAD DATA LOCAL Capability",
        "medium",
        "PRESENT",
        "Disable LOAD DATA LOCAL when it is not required."
      )

    else

      output["LOAD DATA LOCAL"] = "NOT ADVERTISED"

    end

    if has_capability(
      info.capabilities,
      mysql.Capabilities.SupportsCompression
    ) then

      output["Compression"] = "SUPPORTED"

    else

      output["Compression"] = "NOT ADVERTISED"

    end

    if has_capability(
      info.capabilities,
      mysql.Capabilities.Support41Auth
    ) then

      output["4.1 Authentication"] = "SUPPORTED"

    else

      output["4.1 Authentication"] = "NOT ADVERTISED"

      add_finding(
        findings,
        "Legacy Authentication Capability",
        "high",
        "WEAK",
        "Use modern authentication mechanisms supported by the deployed MySQL version."
      )

    end

  end

  if info.extcapabilities then

    if has_capability(
      info.extcapabilities,
      mysql.ExtCapabilities.SupportsAuthPlugins
    ) then

      output["Authentication Plugins"] = "SUPPORTED"

    else

      output["Authentication Plugins"] = "NOT ADVERTISED"

    end

  end

  if info.auth_plugin_name then
    output["Auth Plugin"] = info.auth_plugin_name
  end

  if #findings > 0 then

    local finding_output = stdnse.output_table()

    for _, finding in ipairs(findings) do

      finding_output[finding.name] =
        finding.status ..
        " [" ..
        string.upper(finding.severity) ..
        "]"

    end

    output["Findings"] = finding_output

  else

    output["Findings"] =
      "No MySQL protocol weaknesses detected"

  end

  local score = calculate_score(findings)
  local risk = risk_level(score)

  output["Risk Score"] =
    tostring(score) .. "/100"

  output["Risk Level"] =
    risk

  if #findings > 0 then

    local recommendations =
      stdnse.output_table()

    for _, finding in ipairs(findings) do

      recommendations[finding.name] =
        finding.recommendation

    end

    output["Recommendations"] =
      recommendations

  end

  return output
end
