description = [[
NSE-Sentinel SMB Security Audit

Audits SMB protocol configuration and identifies potentially
weak security settings such as SMBv1 support, weak authentication
configuration, and missing SMB message signing.

The script also collects basic SMB server information for
security assessment and reporting.

Designed for authorized security assessment and laboratory
environments.
]]

author = "Abir Majdi - NSE-Sentinel"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

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

local function audit_dialects(host, findings, output)

  local status, dialects = smb.list_dialects(host)

  if not status or not dialects then
    output["SMB Dialects"] = "Unable to determine"
    return
  end

  local dialect_output = stdnse.output_table()
  local smb1_found = false

  for _, dialect in ipairs(dialects) do

    local label = dialect

    if dialect == "NT LM 0.12" then
      label = "NT LM 0.12 (SMBv1)"
      smb1_found = true
    end

    dialect_output[#dialect_output + 1] = label
  end

  output["SMB Dialects"] = dialect_output

  if smb1_found then

    add_finding(
      findings,
      "SMBv1 Enabled",
      "high",
      "WEAK",
      "Disable SMBv1 and require SMBv2 or newer."
    )

  end
end

local function audit_security_mode(host, findings, output)

  local status, state = smb.start(host)

  if status == false then
    output["Security Mode"] = "Unable to negotiate"
    return
  end

  local overrides = {}

  status = smb.negotiate_protocol(state, overrides)

  if status == false then
    smb.stop(state)
    output["Security Mode"] = "Unable to negotiate"
    return
  end

  local security_mode = state["security_mode"]

  if not security_mode then
    smb.stop(state)
    output["Security Mode"] = "Unknown"
    return
  end

  local security_output = stdnse.output_table()

  ------------------------------------------------------------
  -- Authentication level
  ------------------------------------------------------------

  if (security_mode & 1) == 1 then

    security_output["Authentication"] = "USER"

  else

    security_output["Authentication"] = "SHARE"

    add_finding(
      findings,
      "Share-Level Authentication",
      "high",
      "WEAK",
      "Use user-level authentication instead of share-level authentication."
    )

  end

  ------------------------------------------------------------
  -- Challenge/response
  ------------------------------------------------------------

  if (security_mode & 2) == 0 then

    security_output["Challenge Response"] = "PLAINTEXT ONLY"

    add_finding(
      findings,
      "Plaintext Authentication Supported",
      "high",
      "WEAK",
      "Require challenge/response authentication and disable plaintext authentication."
    )

  else

    security_output["Challenge Response"] = "SUPPORTED"

  end

  ------------------------------------------------------------
  -- Message signing
  ------------------------------------------------------------

  if (security_mode & 8) == 8 then

    security_output["Message Signing"] = "REQUIRED"

  elseif (security_mode & 4) == 4 then

    security_output["Message Signing"] = "SUPPORTED"

    add_finding(
      findings,
      "SMB Message Signing Not Required",
      "medium",
      "WEAK",
      "Require SMB message signing to reduce relay and man-in-the-middle risks."
    )

  else

    security_output["Message Signing"] = "DISABLED"

    add_finding(
      findings,
      "SMB Message Signing Disabled",
      "high",
      "WEAK",
      "Enable and require SMB message signing."
    )

  end

  output["Security Mode"] = security_output

  smb.stop(state)
end

local function collect_os_info(host, output)

  local status, result = smb.get_os(host)

  if status == false or not result then
    return
  end

  local os_output = stdnse.output_table()

  if result.os then
    os_output["OS"] = result.os
  end

  if result.lanmanager then
    os_output["Server"] = result.lanmanager
  end

  if result.server then
    os_output["NetBIOS Name"] = result.server
  end

  if result.domain then
    os_output["Domain"] = result.domain
  end

  if result.workgroup then
    os_output["Workgroup"] = result.workgroup
  end

  if result.fqdn then
    os_output["FQDN"] = result.fqdn
  end

  if result.domain_dns then
    os_output["DNS Domain"] = result.domain_dns
  end

  if result.cpe then
    os_output["CPE"] = result.cpe
  end

  if #os_output > 0 then
    output["SMB Server Information"] = os_output
  end
end

action = function(host)

  local findings = {}
  local output = stdnse.output_table()

  output["Target"] = host.ip

  local smb_port = smb.get_port(host)

  if smb_port then
    output["SMB Port"] = smb_port
  end

  ------------------------------------------------------------
  -- Protocol audit
  ------------------------------------------------------------

  audit_dialects(host, findings, output)

  ------------------------------------------------------------
  -- Security configuration audit
  ------------------------------------------------------------

  audit_security_mode(host, findings, output)

  ------------------------------------------------------------
  -- Server information
  ------------------------------------------------------------

  collect_os_info(host, output)

  ------------------------------------------------------------
  -- Findings
  ------------------------------------------------------------

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
      "No SMB security weaknesses detected"

  end

  ------------------------------------------------------------
  -- Risk score
  ------------------------------------------------------------

  local score = calculate_score(findings)
  local risk = risk_level(score)

  output["Risk Score"] =
    tostring(score) .. "/100"

  output["Risk Level"] =
    risk

  ------------------------------------------------------------
  -- Recommendations
  ------------------------------------------------------------

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
