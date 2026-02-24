# CIS Azure Foundations Benchmark v5.0.0 -- Compliance Checker

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/CISAzureBenchmark?label=PowerShell%20Gallery&color=blue)](https://www.powershellgallery.com/packages/CISAzureBenchmark)
[![Downloads](https://img.shields.io/powershellgallery/dt/CISAzureBenchmark?label=Downloads&color=green)](https://www.powershellgallery.com/packages/CISAzureBenchmark)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.2%2B-blue)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20Benchmark-v5.0.0-orange)](https://www.cisecurity.org/benchmark/azure)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-yellow)](https://buymeacoffee.com/integrateditsolutions)

A PowerShell module that evaluates Azure subscriptions against the **CIS Microsoft Azure Foundations Benchmark v5.0.0**. It runs live checks against Azure Resource Manager and Microsoft Graph APIs, then generates a self-contained HTML dashboard along with JSON and CSV reports showing compliance status.

- **155 controls** covered across 7 service categories
- **93 Automated** checks + **62 Manual** checks with remediation guidance
- **Multi-subscription** scanning with in-dashboard subscription switcher
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

### One-Time Setup

```powershell
# Connect to Azure
Connect-AzAccount

# Connect to Microsoft Graph with required scopes (read-only)
Connect-MgGraph -Scopes "Policy.Read.All,Directory.Read.All,UserAuthenticationMethod.Read.All,Reports.Read.All"

# Register the Security resource provider (required per subscription for Defender checks)
Register-AzResourceProvider -ProviderNamespace Microsoft.Security
```

**PowerShell 7.2 or later** is required.

---

## Usage

### Single Subscription Scan

```powershell
Import-Module CISAzureBenchmark
Invoke-CISAzureBenchmark -OutputDirectory ./reports -OutputFormat All -ProfileLevel 2
```

### Multi-Subscription Scan

```powershell
Invoke-CISAzureBenchmark -AllSubscriptions -OutputDirectory ./reports -OutputFormat All
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
```

### Working with Reports

```powershell
# Re-generate HTML from a saved JSON scan
Export-CISReport -JsonPath ./reports/scan.json -OutputFormat HTML

# List all controls without running checks
Get-CISControlList | Format-Table ControlId, Title, ProfileLevel, AssessmentStatus
```

---

## Report Formats

| Format | Description |
|--------|-------------|
| **HTML** | Self-contained interactive dashboard with executive summary, donut chart, section breakdown, sortable/filterable controls table, expandable detail rows, dark/light mode, and subscription switcher for multi-sub scans. Works offline with zero external dependencies. |
| **JSON** | Machine-readable output with full metadata, suitable for programmatic analysis or re-generating reports via `Export-CISReport`. |
| **CSV** | Flat tabular export for spreadsheet analysis or integration with other compliance tools. |

---

## Exported Functions

| Function | Description |
|----------|-------------|
| `Invoke-CISAzureBenchmark` | Run compliance checks against one or more subscriptions |
| `Get-CISControlList` | List and filter all 155 control definitions without running checks |
| `Export-CISReport` | Re-generate HTML, JSON, or CSV reports from a previously saved JSON scan |

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
