# CIS Azure Foundations Benchmark v5.0.0 -- Compliance Checker

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/CISAzureBenchmark?label=PowerShell%20Gallery&color=blue)](https://www.powershellgallery.com/packages/CISAzureBenchmark)
[![Downloads](https://img.shields.io/powershellgallery/dt/CISAzureBenchmark?label=Downloads&color=green)](https://www.powershellgallery.com/packages/CISAzureBenchmark)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.2%2B-blue)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20Benchmark-v5.0.0-orange)](https://www.cisecurity.org/benchmark/azure)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-yellow)](https://buymeacoffee.com/integrateditsolutions)

A PowerShell module that evaluates Azure subscriptions against the **CIS Microsoft Azure Foundations Benchmark v5.0.0**. It runs live checks against Azure Resource Manager and Microsoft Graph APIs, then generates a self-contained HTML dashboard along with JSON, CSV, and SARIF reports showing compliance status.

- **155 controls** covered across 7 service categories
- **93 Automated** checks + **62 Manual** checks with remediation guidance
- **Multi-subscription** scanning with parallel execution (PS 7+)
- **4 report formats** -- HTML dashboard, JSON, CSV, and SARIF
- **Scan comparison** -- diff/trend analysis between scans
- **Remediation scripts** -- auto-generated PowerShell fix scripts for failed controls
- **Zero external dependencies** -- HTML report works offline and air-gapped
- **Read-only** -- requests only `.Read.All` Graph permissions, never modifies your environment

---

## Security & Permissions

This module is **strictly read-only**. It never creates, modifies, or deletes any Azure resources or Entra ID settings.

**Microsoft Graph scopes requested (all read-only):**

| Scope | Purpose |
|-------|---------|
| `Policy.Read.All` | Read Entra ID authorization and security policies |
| `Directory.Read.All` | Read directory users and roles |
| `UserAuthenticationMethod.Read.All` | Read MFA registration status per user |
| `Reports.Read.All` | Read MFA registration details report |

No `Write`, `ReadWrite`, or `POST`/`PATCH`/`DELETE` calls are made anywhere in the module.

---

## Section Coverage

| Section | Name | Controls | Status | Notes |
|---------|------|----------|--------|-------|
| 1 | Cloud Administration | 0 | N/A | Informational only -- no auditable controls in the benchmark |
| 2 | Analytics Services (Databricks) | 11 | Fully implemented | 6 automated, 5 manual |
| 3 | Compute Services | 1 | Implemented | Manual check (VM update assessment) |
| 4 | Database Services | 0 | N/A | Not in Foundations Benchmark v5.0.0 -- relocated to the separate "CIS Microsoft Azure Database Services Benchmark" |
| 5 | Identity Services (Entra ID) | 42 | Fully implemented | 14 automated, 28 manual; Graph API integration for Entra ID and RBAC |
| 6 | Management and Governance | 25 | Fully implemented | Includes 6.1.3.1, 6.1.4, 6.1.5, and 6.2 (15 automated, 10 manual) |
| 7 | Networking Services | 16 | Fully implemented | 12 automated, 4 manual |
| 8 | Security Services (Defender / Key Vault) | 37 | Fully implemented | 30 automated, 7 manual |
| 9 | Storage Services | 25 | Fully implemented | 16 automated, 9 manual |
| **Total** | | **155** | **Complete** | **93 Automated + 62 Manual** |

---

## Installation

### From PowerShell Gallery

```powershell
Install-Module CISAzureBenchmark -Scope CurrentUser
```

### From Source

```powershell
git clone https://github.com/mohammedsiddiqui6872/CIS-Azure-Foundation-Benchmark.git
Import-Module ./CIS-Azure-Foundation-Benchmark/CISAzureBenchmark/CISAzureBenchmark.psm1
```

> **Note:** The module automatically checks for required Az and Graph modules on first run and installs any that are missing.

---

## Prerequisites

**PowerShell 7.2 or later** is required (PowerShell 5.1 is supported but parallel scanning requires PS 7+).

### Register the Security Resource Provider

This is a one-time requirement per subscription for Defender checks:

```powershell
Register-AzResourceProvider -ProviderNamespace Microsoft.Security
```

---

## Connecting to Azure

The module provides `Connect-CISAzureBenchmark` which handles both Azure and Microsoft Graph connections in a single command.

### Interactive Login (Default)

```powershell
Import-Module CISAzureBenchmark
Connect-CISAzureBenchmark
```

### Service Principal (Client Secret)

```powershell
$credential = Get-Credential   # Username = ApplicationId, Password = Client Secret
Connect-CISAzureBenchmark -ServicePrincipal -Credential $credential -TenantId 'your-tenant-id'
```

### Service Principal (Certificate)

```powershell
Connect-CISAzureBenchmark -ServicePrincipal -ApplicationId 'your-app-id' -CertificateThumbprint 'your-cert-thumbprint' -TenantId 'your-tenant-id'
```

### Managed Identity

```powershell
Connect-CISAzureBenchmark -Identity
```

### Manual Connection (Alternative)

You can also connect manually if you prefer:

```powershell
Connect-AzAccount
Connect-MgGraph -Scopes "Policy.Read.All,Directory.Read.All,UserAuthenticationMethod.Read.All,Reports.Read.All"
```

### Disconnecting

```powershell
Disconnect-CISAzureBenchmark
```

---

## Usage

### Quick Start

```powershell
Import-Module CISAzureBenchmark
Connect-CISAzureBenchmark
Invoke-CISAzureBenchmark -OutputDirectory ./reports -OutputFormat All
```

### Single Subscription Scan

```powershell
Invoke-CISAzureBenchmark -SubscriptionId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -OutputDirectory ./reports
```

### Multi-Subscription Scan

```powershell
# Scans all accessible subscriptions (default behavior)
Invoke-CISAzureBenchmark -OutputDirectory ./reports -OutputFormat All

# Parallel scanning for faster multi-sub scans (PowerShell 7+ only)
Invoke-CISAzureBenchmark -Parallel -ThrottleLimit 5 -OutputDirectory ./reports
```

### Filtered Scans

```powershell
# Only automated checks
Invoke-CISAzureBenchmark -AssessmentStatus Automated

# Only Level 1 controls
Invoke-CISAzureBenchmark -ProfileLevel 1

# Specific sections
Invoke-CISAzureBenchmark -Section '7','8'

# Specific controls
Invoke-CISAzureBenchmark -ControlId '8.1.3.1','9.1.1'

# Exclude controls
Invoke-CISAzureBenchmark -ExcludeControlId '5.2.1','5.2.2'

# Exclude resources by tag
Invoke-CISAzureBenchmark -ExcludeResourceTag @{ Environment = 'dev' }

# Custom config overrides
Invoke-CISAzureBenchmark -ConfigPath ./my-config.psd1

# Suppress auto-opening the HTML report
Invoke-CISAzureBenchmark -NoAutoOpen
```

### Compare Scans (Trend Analysis)

```powershell
# Compare a baseline scan against a current scan
Compare-CISBenchmarkResults -BaselinePath ./reports/baseline.json -CurrentPath ./reports/current.json

# Generate an HTML diff report
Compare-CISBenchmarkResults -BaselinePath ./reports/baseline.json -CurrentPath ./reports/current.json -OutputPath ./reports/diff.html
```

Returns new failures, resolved issues, regressions, improvements, and score delta.

### Generate Remediation Scripts

```powershell
# From a live scan result
$results = Invoke-CISAzureBenchmark
Export-CISRemediationScript -Results $results.Results -OutputPath ./remediation.ps1

# From a saved JSON report
Export-CISRemediationScript -JsonPath ./reports/scan.json -OutputPath ./remediation.ps1
```

Generates a PowerShell script with remediation commands for each failed control, grouped by section.

### Re-generate Reports

```powershell
# Re-generate all report formats from a saved JSON scan
Export-CISReport -JsonPath ./reports/scan.json -OutputFormat All

# Generate only HTML
Export-CISReport -JsonPath ./reports/scan.json -OutputFormat HTML

# Generate SARIF for security tool integration
Export-CISReport -JsonPath ./reports/scan.json -OutputFormat SARIF
```

### List Controls

```powershell
# List all controls
Get-CISControlList | Format-Table ControlId, Title, ProfileLevel, AssessmentStatus

# Filter by severity
Get-CISControlList -Severity High,Critical | Format-Table ControlId, Title, Severity

# Filter by section
Get-CISControlList -Section '8' | Format-Table ControlId, Title, AssessmentStatus
```

---

## Report Formats

| Format | Description |
|--------|-------------|
| **HTML** | Self-contained interactive dashboard with executive summary, donut chart, section breakdown, sortable/filterable controls table, expandable detail rows, dark/light mode, and subscription switcher for multi-sub scans. Works offline with zero external dependencies. |
| **JSON** | Machine-readable output with full metadata, suitable for programmatic analysis, re-generating reports via `Export-CISReport`, or scan comparison via `Compare-CISBenchmarkResults`. |
| **CSV** | Flat tabular export for spreadsheet analysis or integration with other compliance tools. |
| **SARIF** | SARIF v2.1.0 format for integration with security scanning tools, CI/CD pipelines, and GitHub Advanced Security. |

---

## Exported Functions

| Function | Description |
|----------|-------------|
| `Connect-CISAzureBenchmark` | Connect to Azure and Microsoft Graph with support for interactive, service principal, certificate, and managed identity auth |
| `Disconnect-CISAzureBenchmark` | Disconnect from Azure and Microsoft Graph sessions |
| `Invoke-CISAzureBenchmark` | Run compliance checks against one or more subscriptions with filtering and parallel execution |
| `Get-CISControlList` | List and filter all 155 control definitions without running checks |
| `Export-CISReport` | Re-generate HTML, JSON, CSV, or SARIF reports from a previously saved JSON scan |
| `Compare-CISBenchmarkResults` | Compare two scan results to show compliance trends, regressions, and improvements |
| `Export-CISRemediationScript` | Generate a PowerShell remediation script from scan results for failed controls |

---

## Author

**Mohammed Siddiqui**

- GitHub: [@mohammedsiddiqui6872](https://github.com/mohammedsiddiqui6872)
- LinkedIn: [Let's Chat!](https://powershellnerd.com/profile/mohammedsiddiqui)
- Website: [PowerShellNerd](https://powershellnerd.com)
- Support: [Buy Me a Coffee](https://buymeacoffee.com/integrateditsolutions)

---

## Support

For issues, questions, or suggestions:

- [Open an Issue](https://github.com/mohammedsiddiqui6872/CIS-Azure-Foundation-Benchmark/issues)
- [Start a Discussion](https://github.com/mohammedsiddiqui6872/CIS-Azure-Foundation-Benchmark/discussions)
- [PowerShellNerd](https://powershellnerd.com)

### Support This Project

If you find this tool helpful and want to support continued development:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-yellow?style=for-the-badge)](https://buymeacoffee.com/integrateditsolutions)

Your support helps maintain and improve this project!

If you find this tool helpful, please consider giving it a star!

---

## Disclaimer

This toolkit is not affiliated with or endorsed by Microsoft Corporation or CIS (Center for Internet Security). This script is provided as-is for compliance assessment purposes. Always test in a non-production environment first.

---

## License

See [LICENSE](LICENSE) for details.
