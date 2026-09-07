description = [[
NSE-Sentinel FTP Security Audit

Audits FTP service configuration and identifies potentially weak
or insecure settings such as anonymous access, cleartext FTP,
missing TLS support, and legacy service information.

Designed for authorized security assessment and laboratory
environments.
]]

author = "Abir Majdi - NSE-Sentinel"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

local ftp = require "ftp"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

portrule = shortport.port_or_service({21, 990}, {"ftp", "ftps"})

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

local function check_anonymous(socket, buffer)
  local status, code, message = ftp.auth(
    socket,
    buffer,
    "anonymous",
    "IEUser@"
  )

  if status then
    return true, code, message
  end

  return false, code, message
end

local function check_feat(socket, buffer)
  if not socket:send("FEAT\r\n") then
    return nil
  end

  local code, message = ftp.read_reply(buffer)

  if not code then
    return nil
  end

  if code == 211 then
    return message
  end

  return nil
end

local function check_syst(socket, buffer)
  if not socket:send("SYST\r\n") then
    return nil
  end

  local code, message = ftp.read_reply(buffer)

  if not code then
    return nil
  end

  if code == 215 then
    return message
  end

  return nil
end

action = function(host, port)

  local socket, code, message, buffer =
    ftp.connect(host, port, {request_timeout = 8000})

  if not socket then
    stdnse.debug1(
      "Couldn't connect: %s",
      code or message
    )
    return nil
  end

  if code and code ~= 220 then
    stdnse.debug1(
      "Unexpected FTP banner code %d: %q",
      code,
      message
    )
    ftp.close(socket)
    return nil
  end

  local findings = {}
  local output = stdnse.output_table()

  output["Target"] = host.ip
  output["Port"] = port.number

  if message then
    output["FTP Banner"] = message
  end

  ----------------------------------------------------------------
  -- SYST
  ----------------------------------------------------------------

  local syst = check_syst(socket, buffer)

  if syst and syst ~= "" then
    output["SYST"] = syst
  end

  ----------------------------------------------------------------
  -- FEAT
  ----------------------------------------------------------------

  local features = check_feat(socket, buffer)

  if features then
    output["FTP Features"] = features

    local feature_text = string.lower(features)

    if string.find(feature_text, "auth tls", 1, true) or
       string.find(feature_text, "auth ssl", 1, true) then

      output["TLS Support"] = "ADVERTISED"

    else

      output["TLS Support"] = "NOT ADVERTISED"

      add_finding(
        findings,
        "TLS Support Not Advertised",
        "medium",
        "WEAK",
        "Enable and advertise explicit FTPS using AUTH TLS."
      )
    end

  else

    output["FTP Features"] = "FEAT not supported"

    output["TLS Support"] = "UNKNOWN"

    add_finding(
      findings,
      "FEAT Command Not Supported",
      "low",
      "WEAK",
      "Enable FTP FEAT support to advertise available security capabilities."
    )
  end

  ----------------------------------------------------------------
  -- Cleartext FTP
  ----------------------------------------------------------------

  if port.number == 21 then

    add_finding(
      findings,
      "FTP Control Channel Uses Cleartext",
      "medium",
      "PRESENT",
      "Prefer explicit FTPS using AUTH TLS or another secure file transfer protocol."
    )

  elseif port.number == 990 then

    output["Transport"] = "Implicit FTPS"

  end

  ----------------------------------------------------------------
  -- Anonymous authentication
  ----------------------------------------------------------------

  local anonymous, anon_code, anon_message =
    check_anonymous(socket, buffer)

  if anonymous then

    output["Anonymous Access"] =
      "ALLOWED (FTP code " .. tostring(anon_code) .. ")"

    add_finding(
      findings,
      "Anonymous FTP Access",
      "high",
      "PRESENT",
      "Disable anonymous FTP access unless it is explicitly required."
    )

  else

    output["Anonymous Access"] = "DENIED"

  end

  ----------------------------------------------------------------
  -- Close connection
  ----------------------------------------------------------------

  ftp.close(socket)

  ----------------------------------------------------------------
  -- Findings
  ----------------------------------------------------------------

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

    output["Findings"] = "No FTP security weaknesses detected"

  end

  ----------------------------------------------------------------
  -- Risk
  ----------------------------------------------------------------

  local score = calculate_score(findings)
  local risk = risk_level(score)

  output["Risk Score"] =
    tostring(score) .. "/100"

  output["Risk Level"] = risk

  ----------------------------------------------------------------
  -- Recommendations
  ----------------------------------------------------------------

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
