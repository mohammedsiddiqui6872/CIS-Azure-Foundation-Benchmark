# Changelog

All notable changes to the CIS Azure Foundation Benchmark module will be documented in this file.

## [5.1.0] - 2026-02-24

### Added
- Centralized configuration system (`ModuleConfig.psd1`) with `-ConfigPath` parameter override
- `Compare-CISBenchmarkResults` function for diff/trend analysis between scans
- `Export-CISRemediationScript` function for generating remediation guidance scripts
- SARIF v2.1.0 output format for security tool integration (GitHub Code Scanning, Azure DevOps)
- Resource tag-based exclusions via `-ExcludeResourceTag` parameter
- Progress estimation with ETA display during scans
- PSGallery update checker on startup (with `-SkipUpdateCheck` config)
- Pre-cached blob/file service properties to eliminate redundant API calls
- Graph API pagination with configurable page size (`$top` parameter)
- Error message sanitization helper (`Format-CISErrorMessage`)
- Pester test suite restored and enhanced (10 test files, 40+ tests)

### Fixed
- Section filter false positives: `8.1` no longer matches `8.10`, `8.11`, etc.
- MFA fallback N+1 API storm: added throttle protection and user limit
- Score denominator edge case: shows "N/A" instead of "0%" when no evaluated controls
- Single result JSON array handling: uses `-AsArray` flag instead of manual wrapping
- Retry pattern no longer matches "non-transient" errors as retryable
- Empty catch block in Initialize-CISEnvironment now logs to verbose stream
- Network Watcher location fallback uses cached resources instead of expensive Get-AzResource

### Security
- Removed `SkipPublisherCheck` from module auto-installation
- Replaced manual JSON string construction with safe `ConvertTo-Json` serialization
- Added `</script>` sanitization in HTML report data payloads
- Output path validation warns on UNC paths
- Error messages stripped of Azure correlation IDs and stack traces

### Changed
- All hardcoded thresholds (90-day retention, 20-item display limit) now configurable
- AuthorizationFailed errors return WARNING instead of ERROR across all sections
- Module version bumped to 5.1.0
- FunctionsToExport expanded with 2 new public functions

## [5.0.0] - 2026-02-24

### Added
- Complete CIS Microsoft Azure Foundations Benchmark v5.0.0 compliance checker
- 155 controls across 7 service categories (93 Automated + 62 Manual)
- 12 reusable pattern handlers for data-driven check dispatch
- ~35 custom check functions for complex control logic
- Resource pre-fetch caching to avoid N+1 Azure API calls
- Multi-subscription scanning with combined HTML dashboard
- Self-contained HTML report with interactive dashboard (zero external dependencies)
- JSON and CSV report export formats
- Microsoft Graph API integration for Entra ID / Identity checks
- Graph API scope validation with clear warnings for missing permissions
- Retry logic with exponential backoff for Azure API resilience
- Comprehensive Pester test suite
- Security notice for report files containing sensitive data

### Fixed
- Severity override bug where Medium severity was incorrectly overwritten
- Key Vault cache logic bug where custom checks might not trigger caching
- MFA fallback check now validates specific MFA-capable method types
- VM update check no longer unconditionally passes
- Standardized "N/A" wording for controls with no applicable resources
- Compliance score now clearly labeled as "Automated Checks Score"
- WARNING status properly excluded from compliance score denominator

### Security
- All HTML report data properly escaped via escapeHtml() to prevent XSS
- Reports include security sensitivity notice
- .gitignore prevents accidental commit of report files
