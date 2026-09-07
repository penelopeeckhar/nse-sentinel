description = [[
NSE-Sentinel SSH Security Audit

Audits SSH protocol negotiation and identifies potentially weak
cryptographic algorithms and legacy configuration.

Designed for authorized security assessment and laboratory
environments.
]]

author = "Abir Majdi - NSE-Sentinel"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local stringaux = require "stringaux"
local ssh2 = require "ssh2"

portrule = shortport.ssh

local function contains(list, pattern)
  if not list then
    return false
  end

  local values = stringaux.strsplit(",", list)

  for _, value in ipairs(values) do
    if string.find(string.lower(value), pattern, 1, true) then
      return true
    end
  end

  return false
end

local function audit_algorithms(parsed, findings)

  local checks = {
    {
      field = "kex_algorithms",
      pattern = "diffie-hellman-group1-sha1",
      name = "Weak KEX: diffie-hellman-group1-sha1",
      severity = "high",
      recommendation = "Disable diffie-hellman-group1-sha1."
    },
    {
      field = "kex_algorithms",
      pattern = "sha1",
      name = "SHA-1 based KEX",
      severity = "medium",
      recommendation = "Prefer modern key exchange algorithms without SHA-1."
    },
    {
      field = "server_host_key_algorithms",
      pattern = "ssh-dss",
      name = "Weak Host Key: ssh-dss",
      severity = "high",
      recommendation = "Disable DSA/ssh-dss host keys."
    },
    {
      field = "server_host_key_algorithms",
      pattern = "ssh-rsa",
      name = "Legacy Host Key: ssh-rsa",
      severity = "medium",
      recommendation = "Prefer modern host key algorithms where supported."
    },
    {
      field = "encryption_algorithms_client_to_server",
      pattern = "cbc",
      name = "CBC Encryption",
      severity = "medium",
      recommendation = "Prefer modern AEAD or CTR-based encryption algorithms."
    },
    {
      field = "encryption_algorithms_server_to_client",
      pattern = "cbc",
      name = "CBC Encryption",
      severity = "medium",
      recommendation = "Prefer modern AEAD or CTR-based encryption algorithms."
    },
    {
      field = "encryption_algorithms_client_to_server",
      pattern = "arcfour",
      name = "Weak Encryption: arcfour",
      severity = "high",
      recommendation = "Disable arcfour encryption."
    },
    {
      field = "encryption_algorithms_server_to_client",
      pattern = "arcfour",
      name = "Weak Encryption: arcfour",
      severity = "high",
      recommendation = "Disable arcfour encryption."
    },
    {
      field = "encryption_algorithms_client_to_server",
      pattern = "3des",
      name = "Legacy Encryption: 3DES",
      severity = "medium",
      recommendation = "Prefer modern encryption algorithms."
    },
    {
      field = "encryption_algorithms_server_to_client",
      pattern = "3des",
      name = "Legacy Encryption: 3DES",
      severity = "medium",
      recommendation = "Prefer modern encryption algorithms."
    },
    {
      field = "mac_algorithms_client_to_server",
      pattern = "md5",
      name = "Weak MAC: MD5",
      severity = "high",
      recommendation = "Disable MD5-based MAC algorithms."
    },
    {
      field = "mac_algorithms_server_to_client",
      pattern = "md5",
      name = "Weak MAC: MD5",
      severity = "high",
      recommendation = "Disable MD5-based MAC algorithms."
    }
  }

  local seen = {}

  for _, check in ipairs(checks) do

    local value = parsed[check.field]

    if value and contains(value, check.pattern) then

      if not seen[check.name] then

        findings[#findings + 1] = {
          name = check.name,
          severity = check.severity,
          status = "WEAK",
          recommendation = check.recommendation
        }

        seen[check.name] = true
      end
    end
  end
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
    if finding.status == "WEAK" then
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

local function output_algorithms(parsed)

  local algorithms = stdnse.output_table()

  local fields = {
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_algorithms",
    "encryption_algorithms_client_to_server",
    "encryption_algorithms_server_to_client",
    "mac_algorithms",
    "mac_algorithms_client_to_server",
    "mac_algorithms_server_to_client"
  }

  for _, field in ipairs(fields) do

    if parsed[field] then

      local values = stringaux.strsplit(",", parsed[field])

      algorithms[field] = string.format(
        "%d algorithms",
        #values
      )
    end
  end

  return algorithms
end

action = function(host, port)

  local sock = nmap.new_socket()

  local status = sock:connect(host, port)

  if not status then
    return
  end

  status = sock:send(
    "SSH-2.0-NSE-Sentinel_Audit\r\n"
  )

  if not status then
    sock:close()
    return
  end

  status = sock:receive_buf("\r?\n", false)

  if not status then
    sock:close()
    return
  end

  local ssh = ssh2.transport

  status = sock:send(
    ssh.build(ssh.kex_init())
  )

  if not status then
    sock:close()
    return
  end

  local response

  status, response = ssh.receive_packet(sock)

  sock:close()

  if not status then
    return
  end

  local parsed = ssh.parse_kex_init(
    ssh.payload(response)
  )

  local findings = {}

  audit_algorithms(parsed, findings)

  local score = calculate_score(findings)
  local risk = risk_level(score)

  local output = stdnse.output_table()

  output["Target"] = host.ip
  output["Port"] = port.number

  output["SSH Algorithms"] = output_algorithms(parsed)

  local finding_output = stdnse.output_table()

  for _, finding in ipairs(findings) do

    finding_output[finding.name] =
      finding.status ..
      " [" ..
      string.upper(finding.severity) ..
      "]"

  end

  if next(finding_output) then
    output["Findings"] = finding_output
  else
    output["Findings"] = "No weak algorithms detected"
  end

  output["Risk Score"] =
    tostring(score) .. "/100"

  output["Risk Level"] = risk

  local recommendations = stdnse.output_table()

  for _, finding in ipairs(findings) do

    recommendations[finding.name] =
      finding.recommendation

  end

  if next(recommendations) then
    output["Recommendations"] = recommendations
  end

  return output
end
