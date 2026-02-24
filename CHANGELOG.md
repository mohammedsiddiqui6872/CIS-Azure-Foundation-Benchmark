# Changelog

All notable changes to the CIS Azure Foundation Benchmark module will be documented in this file.

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
