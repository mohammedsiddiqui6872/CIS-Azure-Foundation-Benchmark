@{
    RootModule        = 'CISAzureBenchmark.psm1'
    ModuleVersion     = '5.0.0'
    GUID              = 'b8f4e2a1-3c6d-4f89-9a2e-7d1b5c3e8f40'
    Author            = 'Mohammed Siddiqui'
    CompanyName       = 'powershellnerd.com'
    Copyright         = '(c) 2026 Mohammed Siddiqui. All rights reserved.'
    Description       = 'CIS Microsoft Azure Foundations Benchmark v5.0.0 Compliance Checker. Evaluates Azure subscriptions against 155 CIS controls (93 Automated + 62 Manual) covering Identity, Networking, Security, Storage, Analytics, Compute, and Management services. Generates interactive HTML dashboard, JSON, and CSV reports. Supports multi-subscription scanning.'
    PowerShellVersion = '7.2'

    RequiredModules   = @(
        @{ ModuleName = 'Az.Accounts';      ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Az.Security';       ModuleVersion = '1.0.0' }
        @{ ModuleName = 'Az.Network';        ModuleVersion = '4.0.0' }
        @{ ModuleName = 'Az.Storage';        ModuleVersion = '4.0.0' }
        @{ ModuleName = 'Az.KeyVault';       ModuleVersion = '4.0.0' }
        @{ ModuleName = 'Az.Monitor';        ModuleVersion = '3.0.0' }
        @{ ModuleName = 'Az.Resources';      ModuleVersion = '5.0.0' }
        @{ ModuleName = 'Az.Websites';       ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Az.Databricks';     ModuleVersion = '1.0.0' }
    )

    FunctionsToExport = @(
        'Invoke-CISAzureBenchmark'
        'Get-CISControlList'
        'Export-CISReport'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('CIS', 'Azure', 'Benchmark', 'Security', 'Compliance', 'Audit', 'Defender', 'EntraID', 'KeyVault', 'NSG', 'StorageAccount')
            ProjectUri   = 'https://github.com/mohammedsiddiqui6872/CIS-Azure-Foundation-Benchmark'
            LicenseUri   = 'https://github.com/mohammedsiddiqui6872/CIS-Azure-Foundation-Benchmark/blob/main/LICENSE'
            ReleaseNotes = @'
v5.0.0 - Initial release
- 155 CIS controls (93 Automated + 62 Manual) from CIS Azure Foundations Benchmark v5.0.0
- Data-driven pattern dispatch architecture with 12 reusable check handlers
- Resource pre-fetch caching with retry logic for Azure API resilience
- Multi-subscription scanning with combined HTML dashboard
- Self-contained HTML report (zero external dependencies, works offline)
- JSON and CSV export formats
- Microsoft Graph integration for Entra ID / Identity checks with scope validation
- Comprehensive Pester test suite (33 tests)
'@
        }
    }
}
