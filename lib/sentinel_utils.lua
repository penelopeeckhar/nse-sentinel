local M = {}

M.severity_weight = {
  info = 0,
  low = 5,
  medium = 15,
  high = 25,
  critical = 40
}

function M.calculate_score(findings)
  local score = 0

  for _, finding in ipairs(findings) do
    if finding.status == "MISSING" or finding.status == "WEAK" then
      score = score + (M.severity_weight[finding.severity] or 0)
    end
  end

  return math.min(score, 100)
end

function M.risk_level(score)
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

function M.add_finding(findings, name, severity, status, recommendation)
  findings[#findings + 1] = {
    name = name,
    severity = severity,
    status = status,
    recommendation = recommendation
  }
end

return M
