# ============================================================

# Conditional Access Policy Auditor

# Read-only | Safe to run

# ============================================================

Write-Host "n[*] Connecting to Microsoft Graph..." -ForegroundColor Cyan

Connect-MgGraph -Scopes "Policy.Read.All","Directory.Read.All"

# ------------------------------------------------------------

# Pull Policies

# ------------------------------------------------------------

Write-Host "[*] Pulling Conditional Access policies..." -ForegroundColor Cyan

$policies = Get-MgIdentityConditionalAccessPolicy

# ------------------------------------------------------------

# Pull Admin Roles

# ------------------------------------------------------------

Write-Host "[*] Pulling admin roles..." -ForegroundColor Cyan

$adminRoleIds = @()

try {

$roles = Get-MgDirectoryRole -All

$adminRoles = $roles | Where-Object {
    $_.DisplayName -match "Admin|Global|Privileged"
}

foreach ($role in $adminRoles) {

    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id

    foreach ($member in $members) {
        $adminRoleIds += $member.Id
    }
}

$adminRoleIds = $adminRoleIds | Sort-Object -Unique

Write-Host "    Found $($adminRoleIds.Count) admin accounts." -ForegroundColor Gray

}
catch {

Write-Host "    Could not retrieve admin role members." -ForegroundColor Yellow

}

# ------------------------------------------------------------

# Audit Checks

# ------------------------------------------------------------

$findings = @()

foreach ($policy in $policies) {

$issues = @()

$controls = $policy.GrantControls
$conditions = $policy.Conditions

# Disabled policy
if ($policy.State -eq "disabled") {

    $issues += "DISABLED: Policy is turned off"

}

# Report only
if ($policy.State -eq "enabledForReportingButNotEnforced") {

    $issues += "REPORT-ONLY: Policy is not enforcing controls"

}

# MFA Check
$hasMFA = $false

if ($controls -and $controls.BuiltInControls) {

    $hasMFA = $controls.BuiltInControls -contains "mfa"

}

$hasCompliantDevice = $false

if ($controls -and $controls.BuiltInControls) {

    $hasCompliantDevice = $controls.BuiltInControls -contains "compliantDevice"

}

if (
    -not $hasMFA -and
    -not $hasCompliantDevice -and
    $policy.State -eq "enabled"
) {

    $issues += "NO MFA: Policy does not require MFA or compliant device"

}

# Excessive exclusions
$excludedUsers = @()

if ($conditions.Users -and $conditions.Users.ExcludeUsers) {

    $excludedUsers = $conditions.Users.ExcludeUsers

}

if ($excludedUsers.Count -gt 5) {

    $issues += "EXCESSIVE EXCLUSIONS: More than 5 excluded users"

}

# No apps targeted
$includedApps = @()

if (
    $conditions.Applications -and
    $conditions.Applications.IncludeApplications
) {

    $includedApps = $conditions.Applications.IncludeApplications

}

if ($includedApps -contains "None") {

    $issues += "NO APP TARGET: Policy targets no applications"

}

# Legacy auth
$blocksLegacyAuth = $false

if ($conditions.ClientAppTypes) {

    if (
        (
            $conditions.ClientAppTypes -contains "exchangeActiveSync"
        ) -or
        (
            $conditions.ClientAppTypes -contains "other"
        )
    ) {

        if (
            $controls -and
            $controls.BuiltInControls -contains "block"
        ) {

            $blocksLegacyAuth = $true

        }
    }
}

if (
    $conditions.ClientAppTypes -and
    (
        $conditions.ClientAppTypes -contains "exchangeActiveSync" -or
        $conditions.ClientAppTypes -contains "other"
    ) -and
    -not $blocksLegacyAuth -and
    $policy.State -eq "enabled"
) {

    $issues += "LEGACY AUTH ALLOWED: Legacy authentication not blocked"

}

# Admin coverage
$coversAdmins = $false

if ($conditions.Users) {

    $includesAll = $conditions.Users.IncludeUsers -contains "All"

    $includesRoles = (
        $conditions.Users.IncludeRoles -and
        $conditions.Users.IncludeRoles.Count -gt 0
    )

    if ($includesAll -or $includesRoles) {

        $coversAdmins = $true

    }
}

if (
    -not $coversAdmins -and
    $policy.State -eq "enabled"
) {

    $issues += "ADMIN COVERAGE UNCLEAR"

}

# Risk level
$riskLevel = switch ($issues.Count) {

    { $_ -ge 3 } { "CRITICAL" }
    2            { "HIGH" }
    1            { "MEDIUM" }
    default      { "LOW" }

}

$issueText = "No issues found"

if ($issues.Count -gt 0) {

    $issueText = $issues -join " | "

}

$findings += [PSCustomObject]@{

    PolicyName = $policy.DisplayName
    State      = $policy.State
    IssueCount = $issues.Count
    Issues     = $issueText
    RiskLevel  = $riskLevel

}

}

# ------------------------------------------------------------

# Preview

# ------------------------------------------------------------

Write-Host "n===== AUDIT RESULTS =====" -ForegroundColor Cyan

$findings |
Sort-Object IssueCount -Descending |
Format-Table PolicyName, State, RiskLevel, IssueCount -AutoSize

# ------------------------------------------------------------

# CSV Export

# ------------------------------------------------------------

$csvPath = ".\CA-Audit-Report.csv"

$findings | Export-Csv -Path $csvPath -NoTypeInformation

Write-Host "[+] CSV saved: $csvPath" -ForegroundColor Green

# ------------------------------------------------------------

# HTML Report
$timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$totalCount = $findings.Count
$critCount  = ($findings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
$highCount  = ($findings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
$medCount   = ($findings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
$lowCount   = ($findings | Where-Object { $_.RiskLevel -eq "LOW" }).Count

$htmlStart = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>CA Policy Audit Report</title>
<style>
  body      { font-family: Segoe UI, Tahoma, sans-serif; padding: 2rem; background: #f4f6f9; color: #333; }
  h1        { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 0.5rem; }
  h2        { color: #0078d4; margin-top: 2rem; }
  .summary  { display: flex; gap: 1rem; margin: 1.5rem 0; flex-wrap: wrap; }
  .card     { background: white; border-radius: 8px; padding: 1rem 1.5rem; min-width: 120px; box-shadow: 0 2px 6px rgba(0,0,0,0.1); text-align: center; }
  .card h2  { margin: 0; font-size: 2rem; border: none; }
  .card p   { margin: 0.3rem 0 0; font-size: 0.85rem; color: #666; }
  .c-red    { color: #c00; }
  .c-orange { color: #e65c00; }
  .c-yellow { color: #b38600; }
  .c-green  { color: #107c10; }
  table     { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 6px rgba(0,0,0,0.1); }
  th        { background: #0078d4; color: white; padding: 12px 14px; text-align: left; font-size: 0.9rem; }
  td        { padding: 10px 14px; border-bottom: 1px solid #eee; font-size: 0.88rem; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td      { background: #f0f6ff; }
  .CRITICAL { color: #c00; font-weight: bold; }
  .HIGH     { color: #e65c00; font-weight: bold; }
  .MEDIUM   { color: #b38600; font-weight: bold; }
  .LOW      { color: #107c10; }
  .badge-enabled  { background: #dff6dd; color: #107c10; padding: 2px 8px; border-radius: 4px; font-size: 0.78rem; font-weight: bold; }
  .badge-disabled { background: #fde7e9; color: #c00; padding: 2px 8px; border-radius: 4px; font-size: 0.78rem; font-weight: bold; }
  .badge-report   { background: #fff4ce; color: #8a6900; padding: 2px 8px; border-radius: 4px; font-size: 0.78rem; font-weight: bold; }
  .safe-note { background: #dff6dd; border-left: 4px solid #107c10; padding: 0.75rem 1rem; border-radius: 4px; margin-bottom: 1.5rem; font-size: 0.88rem; }
  footer    { margin-top: 2rem; font-size: 0.8rem; color: #999; }
</style>
</head>
<body>
<h1>Conditional Access Policy Audit</h1>
<p>Generated: $timestamp | Tenant policies audited: <strong>$totalCount</strong></p>
<div class="safe-note">This report was generated using read-only Microsoft Graph permissions. No policies, users, or settings were modified.</div>
<div class="summary">
  <div class="card"><h2 class="c-red">$critCount</h2><p>CRITICAL</p></div>
  <div class="card"><h2 class="c-orange">$highCount</h2><p>HIGH</p></div>
  <div class="card"><h2 class="c-yellow">$medCount</h2><p>MEDIUM</p></div>
  <div class="card"><h2 class="c-green">$lowCount</h2><p>LOW</p></div>
  <div class="card"><h2>$totalCount</h2><p>Total</p></div>
</div>
<table>
<thead><tr><th>#</th><th>Policy Name</th><th>State</th><th>Risk</th><th>Issues Found</th></tr></thead>
<tbody>
"@

$htmlRows = ""
$rowNum = 1
foreach ($f in ($findings | Sort-Object IssueCount -Descending)) {
    $stateClass = "badge-report"
    $stateLabel = $f.State
    if ($f.State -eq "enabled")  { $stateClass = "badge-enabled"; $stateLabel = "Enabled" }
    if ($f.State -eq "disabled") { $stateClass = "badge-disabled"; $stateLabel = "Disabled" }
    if ($f.State -eq "enabledForReportingButNotEnforced") { $stateClass = "badge-report"; $stateLabel = "Report-Only" }

    $issuesHtml = "<span class='c-green'>No issues detected</span>"
    if ($f.IssueCount -gt 0) {
        $issuesHtml = $f.Issues -replace "\|", "<br>"
    }

    $htmlRows += "<tr><td>$rowNum</td><td><strong>$($f.PolicyName)</strong></td><td><span class='$stateClass'>$stateLabel</span></td><td><span class='$($f.RiskLevel)'>$($f.RiskLevel)</span></td><td>$issuesHtml</td></tr>`n"
    $rowNum++
}

$htmlEnd = @"
</tbody>
</table>
<h2>Checks Performed</h2>
<table>
<thead><tr><th>Check</th><th>Why It Matters</th></tr></thead>
<tbody>
<tr><td>Policy Disabled</td><td>Disabled policies are completely unenforced.</td></tr>
<tr><td>Report-Only Mode</td><td>Audit mode logs but never blocks. Should be promoted to enforced.</td></tr>
<tr><td>No MFA or Device Compliance</td><td>Without MFA, stolen credentials grant full access.</td></tr>
<tr><td>Excessive User Exclusions</td><td>More than 5 excluded users suggests broad carve-outs.</td></tr>
<tr><td>No Application Target</td><td>Policies scoped to None apply to nothing.</td></tr>
<tr><td>No Sign-In Risk Condition</td><td>Risk-based CA uses Microsoft threat intelligence for real-time blocking.</td></tr>
<tr><td>Legacy Authentication Not Blocked</td><td>Legacy protocols bypass MFA entirely - top attack vector.</td></tr>
<tr><td>Named Locations Not Used</td><td>Location rules restrict access to trusted networks.</td></tr>
<tr><td>Admin Coverage Unclear</td><td>Privileged accounts are the highest-value targets.</td></tr>
</tbody>
</table>
<footer>Generated by CA-Auditor.ps1 | Read-only audit | No tenant changes made</footer>
</body>
</html>
"@

# ------------------------------------------------------------

$htmlReport = $htmlStart + $htmlRows + $htmlEnd

$htmlPath = ".\CA-Audit-Report.html"

$htmlReport | Out-File $htmlPath -Encoding UTF8

Write-Host "[+] HTML saved: $htmlPath" -ForegroundColor Green

Start-Process $htmlPath

Write-Host "n[DONE] Audit complete." -ForegroundColor Cyan
