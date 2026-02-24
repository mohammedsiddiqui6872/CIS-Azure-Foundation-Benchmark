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

## Architecture

### Data-Driven Pattern Dispatch

Instead of writing 155 separate functions, controls are defined as **data** in a single definitions file (`ControlDefinitions.psd1`). Each control specifies a `CheckPattern` that dispatches to a reusable handler. Only ~34 controls need custom logic; the rest are handled by 12 parameterized pattern handlers.

| Pattern | Controls | Description |
|---------|----------|-------------|
| `DefenderPlan` | 14 | Check Microsoft Defender for Cloud pricing tier |
| `ActivityLogAlert` | 11 | Match activity log alert conditions by OperationName |
| `NSGPortCheck` | 4 | Scan NSGs for unrestricted internet-facing ports |
| `StorageAccountProperty` | ~12 | Validate storage account configuration properties |
| `StorageBlobProperty` | 3 | Blob service properties (soft delete, versioning) |
| `StorageFileProperty` | 3 | File share properties (SMB version, encryption) |
| `KeyVaultProperty` | 3 | Key Vault configuration checks |
| `KeyVaultKeyExpiry` | 2 | Key expiration date validation |
| `KeyVaultSecretExpiry` | 2 | Secret expiration date validation |
| `DiagnosticSetting` | 4 | Diagnostic settings per resource type |
| `GraphAPIProperty` | 5 | Microsoft Graph / Entra ID policy checks |
| `ManualCheck` | 62 | Returns INFO status with remediation guidance |
| `Custom` | ~34 | Unique logic per control |

### Resource Caching with Retry Logic

Shared Azure resources (storage accounts, NSGs, key vaults, activity log alerts, etc.) are fetched **once** before all checks run, avoiding N+1 API calls and improving scan performance. All Azure API calls are wrapped in retry logic with exponential backoff to handle transient failures and HTTP 429 throttling.

### Graph API Scope Validation

On startup the module validates that the connected Microsoft Graph session has the required scopes (`Policy.Read.All`, `Directory.Read.All`) and optional scopes (`UserAuthenticationMethod.Read.All`, `Reports.Read.All`). Missing scopes produce clear warnings with the exact `Connect-MgGraph` command to fix them.

### Score Calculation

```
Automated Checks Score = PASS / (Total - INFO - WARNING) * 100
```

The "Automated Checks Score" excludes manual checks (INFO) and indeterminate results (WARNING) from the denominator so they do not penalize the score. Manual and indeterminate controls still appear in the report with full guidance.

---

## Module Structure

```
CISAzureBenchmark/
  CISAzureBenchmark.psd1               Module manifest (v5.0.0)
  CISAzureBenchmark.psm1               Root loader (dot-sources all .ps1 files)

  Data/
    ControlDefinitions.psd1            All 155 controls defined as data
    HtmlTemplate.html                  Self-contained HTML dashboard template

  Private/
    Initialize-CISEnvironment.ps1      Validate Az/Graph auth and subscriptions
    New-CISCheckResult.ps1             Standardized result object factory
    Write-CISProgress.ps1              Progress bar helper
    Invoke-CISCheckSafely.ps1          Try/catch wrapper and pattern dispatch
    Invoke-WithRetry.ps1               Exponential backoff retry for API calls
    Invoke-ResourceCheck.ps1           Reusable resource iteration helper
    Get-CISCachedResource.ps1          Resource cache initialization

  Checks/
    CommonPatterns.ps1                 12 reusable pattern handlers
    Section02-AnalyticsServices.ps1    Custom Databricks checks
    Section03-ComputeServices.ps1      Compute checks (manual)
    Section05-IdentityServices.ps1     Custom Entra ID / RBAC checks
    Section06-ManagementGovernance.ps1 Custom management and governance checks
    Section07-Networking.ps1           Custom networking checks
    Section08-SecurityServices.ps1     Custom Defender / Key Vault / Bastion checks
    Section09-StorageServices.ps1      Custom storage checks

  Reports/
    New-CISHtmlReport.ps1              HTML dashboard generator
    New-CISJsonReport.ps1              JSON report generator
    New-CISCsvReport.ps1               CSV report generator

  Public/
    Invoke-CISAzureBenchmark.ps1       Main entry point
    Get-CISControlList.ps1             List and filter controls
    Export-CISReport.ps1               Re-generate reports from saved JSON
```

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

## v5.0.0 Changes and Fixes

### Added
- Complete CIS Microsoft Azure Foundations Benchmark v5.0.0 compliance checker
- 155 controls across 7 service categories (93 Automated + 62 Manual)
- 12 reusable pattern handlers for data-driven check dispatch
- Resource pre-fetch caching to avoid N+1 Azure API calls
- Multi-subscription scanning with combined HTML dashboard
- Retry logic with exponential backoff for Azure API resilience
- Graph API scope validation with clear warnings for missing permissions
- Security notice for report files containing sensitive data

### Fixed
- Severity override bug where Medium severity was incorrectly overwritten
- Key Vault cache logic bug where custom checks might not trigger caching
- MFA fallback check now validates specific MFA-capable method types
- VM update check no longer unconditionally passes
- ProfileLevel bug where Level 2 controls were reported as Level 1
- Compliance score now clearly labeled as "Automated Checks Score"
- WARNING status properly excluded from compliance score denominator

### Security
- All HTML report data escaped via `escapeHtml()` to prevent XSS
- `.gitignore` prevents accidental commit of report files containing subscription and tenant details

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
