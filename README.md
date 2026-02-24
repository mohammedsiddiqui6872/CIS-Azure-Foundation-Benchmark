# CIS Azure Foundations Benchmark v5.0.0 -- Compliance Checker

A PowerShell module that evaluates Azure subscriptions against the **CIS Microsoft Azure Foundations Benchmark v5.0.0**. It runs live checks against Azure Resource Manager and Microsoft Graph APIs, then generates a self-contained HTML dashboard along with JSON and CSV reports showing compliance status.

- **155 controls** covered across 7 service categories
- **93 Automated** checks + **62 Manual** checks with remediation guidance
- **Multi-subscription** scanning with in-dashboard subscription switcher
- **Zero external dependencies** -- HTML report works offline and air-gapped

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

---

## Prerequisites

### Azure PowerShell Modules

```powershell
Install-Module Az.Accounts, Az.Security, Az.Network, Az.Storage, Az.KeyVault, Az.Monitor, Az.Resources, Az.Databricks, Az.Websites -Scope CurrentUser -Force
```

### Microsoft Graph Modules (for Identity checks)

```powershell
Install-Module Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users -Scope CurrentUser -Force
```

### One-Time Setup

```powershell
# Register the Security resource provider (required per subscription for Defender checks)
Register-AzResourceProvider -ProviderNamespace Microsoft.Security

# Connect to Azure
Connect-AzAccount

# Connect to Microsoft Graph with required scopes
Connect-MgGraph -Scopes "Policy.Read.All,Directory.Read.All,UserAuthenticationMethod.Read.All"
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

## License

See [LICENSE](LICENSE) for details.
