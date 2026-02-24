@{
    RootModule        = 'CISAzureBenchmark.psm1'
    ModuleVersion     = '5.1.0'
    GUID              = 'b8f4e2a1-3c6d-4f89-9a2e-7d1b5c3e8f40'
    Author            = 'Mohammed Siddiqui'
    CompanyName       = 'powershellnerd.com'
    Copyright         = '(c) 2026 Mohammed Siddiqui. All rights reserved.'
    Description       = 'CIS Microsoft Azure Foundations Benchmark v5.0.0 Compliance Checker. Evaluates Azure subscriptions against 155 CIS controls (93 Automated + 62 Manual) covering Identity, Networking, Security, Storage, Analytics, Compute, and Management services. Generates interactive HTML dashboard, JSON, and CSV reports. Supports multi-subscription scanning.'
    PowerShellVersion = '5.1'

    # Dependencies are checked and auto-installed at runtime by Initialize-CISEnvironment
    # RequiredModules removed to allow module import before dependencies are installed

    FunctionsToExport = @(
        'Connect-CISAzureBenchmark'
        'Invoke-CISAzureBenchmark'
        'Get-CISControlList'
        'Export-CISReport'
        'Compare-CISBenchmarkResults'
        'Export-CISRemediationScript'
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
v5.1.0 - Bug fixes, security hardening, performance, and new features
- Fixed: Section filter false positives (8.1 no longer matches 8.10, 8.11)
- Fixed: MFA fallback N+1 API storm with throttle protection and user limits
- Fixed: Score shows N/A instead of 0% when no evaluated controls
- Fixed: Retry logic no longer matches "non-transient" as retryable
- Security: Removed SkipPublisherCheck from auto-install
- Security: Replaced manual JSON construction with safe ConvertTo-Json
- Security: Added output path validation and script injection prevention
- Security: Error messages sanitized to prevent information leakage
- Performance: Blob/file service properties pre-cached (eliminates redundant API calls)
- Performance: Graph API pagination with configurable page size
- Performance: Network Watcher location fallback uses cached resources
- Performance: Progress estimation with ETA display
- New: Centralized configuration system (ModuleConfig.psd1 + ConfigPath parameter)
- New: Compare-CISBenchmarkResults for diff/trend analysis between scans
- New: Export-CISRemediationScript for generating remediation guidance scripts
- New: SARIF v2.1.0 output format for security tool integration
- New: Resource tag-based exclusions (-ExcludeResourceTag parameter)
- New: PSGallery update checker on startup
- Quality: Magic numbers replaced with configurable values
- Quality: AuthorizationFailed-specific exception handling across all sections
- Quality: Pester test suite restored and enhanced
'@
        }
    }
}
