$ErrorActionPreference = 'Continue'

# Import the module
Import-Module (Join-Path $PSScriptRoot 'CISAzureBenchmark' 'CISAzureBenchmark.psm1') -Force

# Run the benchmark scan across ALL subscriptions
$result = Invoke-CISAzureBenchmark `
    -AllSubscriptions `
    -OutputDirectory (Join-Path $PSScriptRoot 'reports') `
    -OutputFormat All `
    -ProfileLevel 2 `
    -AssessmentStatus All

# Output report paths
if ($result.ReportPaths) {
    Write-Host "`n  Report files:" -ForegroundColor Cyan
    foreach ($key in $result.ReportPaths.Keys) {
        Write-Host "    $key : $($result.ReportPaths[$key])" -ForegroundColor White
    }
}

# Open HTML in browser
if ($result.ReportPaths.HTML -and (Test-Path $result.ReportPaths.HTML)) {
    Write-Host "`n  Opening HTML dashboard in browser..." -ForegroundColor Green
    Start-Process $result.ReportPaths.HTML
}
