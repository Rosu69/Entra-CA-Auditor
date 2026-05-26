# Entra ID Conditional Access Auditor

A PowerShell script that connects to Microsoft Entra ID via the Graph API,
audits all Conditional Access policies against Microsoft best practices,
and outputs a color-coded HTML + CSV gap report.

## What it checks

| # | Check | Why it matters |
|---|-------|---------------|
| 1 | Disabled policies | Not enforced at all |
| 2 | Report-only mode | Logs but never blocks |
| 3 | No MFA or device compliance | Credentials alone = full access |
| 4 | Excessive user exclusions | Policy defeated by carve-outs |
| 5 | No application target | Policy scoped to nothing |
| 6 | No sign-in risk condition | Missing real-time threat intelligence |
| 7 | Legacy auth not blocked | IMAP/POP3/SMTP bypass MFA |
| 8 | Named locations not used | Missing network trust controls |
| 9 | Admin coverage unclear | Privileged accounts unprotected |

## Requirements

- PowerShell 5.1 or later
- Microsoft Graph PowerShell SDK
- Entra ID account with Security Reader role (read-only)

## Setup

Powershell commands
1. Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
2. Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
3. Install-Module Microsoft.Graph -Scope CurrentUser
4.  4 Get-Module Microsoft.Graph -ListAvailable | Select-Object Name, Version
5. Connect-MgGraph -Scopes "Policy.Read.All", "Directory.Read.All" #Type A for Always run
6. cd C:\to your desired file location
7. Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
8. .\CA-Auditor.ps1
9. If it gives u error cmd not found then; Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass
10. Then try cmd .\CA-Auditor.ps1 again

## Usage

Powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

.\CA-Auditor.ps1
<img width="1574" height="734" alt="Screenshot 2026-05-26 144147" src="https://github.com/user-attachments/assets/5736d835-e017-4e6c-ab20-9df492a555c6" />


Outputs 'CA-Audit-Report.html' and 'CA-Audit-Report.csv' in the current directory.
<img width="1066" height="142" alt="image" src="https://github.com/user-attachments/assets/e8aecbc3-6dcd-449b-897f-d0e1227bbe69" />


## Safety

This script uses read-only Graph API scopes ('Policy.Read.All', 'Directory.Read.All').
No policies, users, or settings are modified. Safe to run in production tenants.

## Author

Roshan Tamang https://www.linkedin.com/in/roshan-tamangg/
