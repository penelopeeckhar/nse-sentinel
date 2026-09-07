description = [[
NSE-Sentinel HTTP Security Audit

Audits HTTP response headers, server information disclosure,
cookie security attributes and HTTP methods.

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

local function lower_headers(response)
  local headers = {}

  if response and response.header then
    for name, value in pairs(response.header) do
      headers[string.lower(name)] = value
    end
  end

  return headers
end

local function check_headers(headers, findings)

  local security_headers = {
    {
      header = "strict-transport-security",
      name = "HSTS",
      severity = "medium",
      recommendation = "Enable Strict-Transport-Security on HTTPS services."
    },
    {
      header = "content-security-policy",
      name = "Content-Security-Policy",
      severity = "medium",
      recommendation = "Define an appropriate Content-Security-Policy."
    },
    {
      header = "x-content-type-options",
      name = "X-Content-Type-Options",
      severity = "low",
      recommendation = "Set X-Content-Type-Options to nosniff."
    },
    {
      header = "x-frame-options",
      name = "X-Frame-Options",
      severity = "low",
      recommendation = "Set X-Frame-Options or CSP frame-ancestors."
    }
  }

  for _, item in ipairs(security_headers) do
    if headers[item.header] then
      table.insert(findings, {
        name = item.name,
        severity = "info",
        status = "PRESENT",
        recommendation = ""
      })
    else
      table.insert(findings, {
        name = item.name,
        severity = item.severity,
        status = "MISSING",
        recommendation = item.recommendation
      })
    end
  end
end

local function check_server(headers, findings)

  if headers["server"] then
    table.insert(findings, {
      name = "Server Information Disclosure",
      severity = "low",
      status = "PRESENT",
      recommendation = "Minimize unnecessary server version information."
    })
  end
end

local function check_cookies(headers, findings)

  local cookie = headers["set-cookie"]

  if cookie then

    local lower_cookie = string.lower(cookie)

    if not string.find(lower_cookie, "httponly", 1, true) then
      table.insert(findings, {
        name = "Cookie HttpOnly",
        severity = "medium",
        status = "MISSING",
        recommendation = "Add the HttpOnly attribute to sensitive cookies."
      })
    end

    if not string.find(lower_cookie, "secure", 1, true) then
      table.insert(findings, {
        name = "Cookie Secure",
        severity = "medium",
        status = "MISSING",
        recommendation = "Add the Secure attribute when cookies are transmitted over HTTPS."
      })
    end

  end
end

local function calculate_score(findings)

  local score = 0

  for _, finding in ipairs(findings) do

    if finding.status == "MISSING" then

      if finding.severity == "medium" then
        score = score + 15
      elseif finding.severity == "low" then
        score = score + 5
      end

    end

  end

  if score > 100 then
    score = 100
  end

  return score
end

local function risk_level(score)

  if score >= 60 then
    return "HIGH"
  elseif score >= 30 then
    return "MEDIUM"
  elseif score > 0 then
    return "LOW"
  else
    return "INFORMATIONAL"
  end
end

action = function(host, port)

  local response = http.head(host, port, "/")

  if not response then
    return "Unable to retrieve HTTP response."
  end

  local headers = lower_headers(response)
  local findings = {}

  check_headers(headers, findings)
  check_server(headers, findings)
  check_cookies(headers, findings)

  local score = calculate_score(findings)
  local risk = risk_level(score)

  local output = stdnse.output_table()

  output["Target"] = host.ip
  output["Port"] = port.number
  output["HTTP Status"] = response.status or "unknown"

  if headers["server"] then
    output["Server"] = headers["server"]
  end

  local finding_output = stdnse.output_table()

  for _, finding in ipairs(findings) do

    local value = finding.status

    if finding.severity ~= "info" then
      value = value .. " [" .. string.upper(finding.severity) .. "]"
    end

    finding_output[finding.name] = value
  end

  output["Findings"] = finding_output
  output["Risk Score"] = tostring(score) .. "/100"
  output["Risk Level"] = risk

  local recommendations = stdnse.output_table()

  for _, finding in ipairs(findings) do

    if finding.recommendation ~= "" and
       finding.status == "MISSING" then

      recommendations[finding.name] = finding.recommendation
    end

  end

  if next(recommendations) then
    output["Recommendations"] = recommendations
  end

  return output
end
