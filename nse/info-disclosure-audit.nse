description = [[
NSE-Sentinel Information Disclosure Audit

Performs a safe HTTP information-disclosure audit.
The script identifies technology and implementation details
exposed through HTTP response headers and HTML metadata.

The audit focuses on passive information gathering and does
not attempt authentication, exploitation, brute force, or
access to sensitive files.

Designed for authorized security assessment and laboratory
environments.
]]

author = "Abir Majdi - NSE-Sentinel"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

portrule = shortport.http

local function add_finding(findings, name, severity, status, value, recommendation)
  findings[#findings + 1] = {
    name = name,
    severity = severity,
    status = status,
    value = value,
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
    if finding.status == "PRESENT" or finding.status == "EXPOSED" then
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

local function header_value(response, name)
  if not response.header then
    return nil
  end

  for key, value in pairs(response.header) do
    if string.lower(key) == string.lower(name) then
      return value
    end
  end

  return nil
end

local function check_header(
    response,
    findings,
    output,
    header_name,
    finding_name,
    severity,
    recommendation)
  
  local value = header_value(response, header_name)

  if value then
    output[header_name] = value

    add_finding(
      findings,
      finding_name,
      severity,
      "EXPOSED",
      value,
      recommendation
    )
  end
end

local function check_html_metadata(body, findings, output)
  if not body then
    return
  end

  local metadata = stdnse.output_table()

  local generator = string.match(
    body,
    '<meta%s+name=["\']generator["\']%s+content=["\']([^"\']+)["\']'
  )

  if not generator then
    generator = string.match(
      body,
      '<meta%s+content=["\']([^"\']+)["\']%s+name=["\']generator["\']'
    )
  end

  if generator then
    metadata["Generator"] = generator

    add_finding(
      findings,
      "HTML Generator Disclosure",
      "low",
      "EXPOSED",
      generator,
      "Remove unnecessary generator metadata from production pages."
    )
  end

  local comment_count = 0

  for _ in string.gmatch(body, "<!%-%-") do
    comment_count = comment_count + 1
  end

  if comment_count > 0 then
    metadata["HTML Comments"] = tostring(comment_count)

    add_finding(
      findings,
      "HTML Comments Exposed",
      "low",
      "PRESENT",
      tostring(comment_count),
      "Review HTML comments and remove internal implementation details."
    )
  end

  if #metadata > 0 then
    output["HTML Metadata"] = metadata
  end
end

action = function(host, port)
  local output = stdnse.output_table()
  local findings = {}

  output["Target"] = host.ip
  output["Port"] = port.number

  local response = http.get(host, port, "/")

  if not response then
    output["HTTP Error"] = "Unable to retrieve HTTP response"
    return output
  end

  if response.status then
    output["HTTP Status"] = tostring(response.status)
  end

  if response.header then

    check_header(
      response,
      findings,
      output,
      "Server",
      "Server Version Disclosure",
      "low",
      "Hide unnecessary server and version information."
    )

    check_header(
      response,
      findings,
      output,
      "X-Powered-By",
      "Technology Stack Disclosure",
      "low",
      "Remove X-Powered-By from production HTTP responses."
    )

    check_header(
      response,
      findings,
      output,
      "X-AspNet-Version",
      "ASP.NET Version Disclosure",
      "low",
      "Remove ASP.NET version disclosure from HTTP responses."
    )

    check_header(
      response,
      findings,
      output,
      "X-AspNetMvc-Version",
      "ASP.NET MVC Version Disclosure",
      "low",
      "Remove ASP.NET MVC version disclosure."
    )

    check_header(
      response,
      findings,
      output,
      "X-Generator",
      "Framework Generator Disclosure",
      "low",
      "Remove framework generator information from responses."
    )

    check_header(
      response,
      findings,
      output,
      "Via",
      "Proxy Information Disclosure",
      "low",
      "Review proxy headers and hide unnecessary infrastructure details."
    )

    check_html_metadata(
      response.body,
      findings,
      output
    )
  end

  if #findings > 0 then

    local finding_output = stdnse.output_table()

    for _, finding in ipairs(findings) do
      local value = ""

      if finding.value then
        value = ": " .. tostring(finding.value)
      end

      finding_output[finding.name] =
        finding.status ..
        value ..
        " [" ..
        string.upper(finding.severity) ..
        "]"
    end

    output["Findings"] = finding_output

  else
    output["Findings"] =
      "No obvious information disclosure detected"
  end

  local score = calculate_score(findings)
  local risk = risk_level(score)

  output["Risk Score"] = tostring(score) .. "/100"
  output["Risk Level"] = risk

  if #findings > 0 then

    local recommendations = stdnse.output_table()

    for _, finding in ipairs(findings) do
      recommendations[finding.name] =
        finding.recommendation
    end

    output["Recommendations"] = recommendations
  end

  return output
end
