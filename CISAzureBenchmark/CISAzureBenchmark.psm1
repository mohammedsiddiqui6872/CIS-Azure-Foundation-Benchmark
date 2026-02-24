# CIS Microsoft Azure Foundations Benchmark v5.0.0 - Compliance Checker Module
# Covers all 155 controls (93 Automated + 62 Manual)

$ModuleRoot = $PSScriptRoot

# Dot-source all function files in order: Private -> Checks -> Reports -> Public
$Private = @(Get-ChildItem -Path "$ModuleRoot/Private/*.ps1" -ErrorAction SilentlyContinue)
$Checks  = @(Get-ChildItem -Path "$ModuleRoot/Checks/*.ps1"  -ErrorAction SilentlyContinue)
$Reports = @(Get-ChildItem -Path "$ModuleRoot/Reports/*.ps1" -ErrorAction SilentlyContinue)
$Public  = @(Get-ChildItem -Path "$ModuleRoot/Public/*.ps1"  -ErrorAction SilentlyContinue)

foreach ($file in @($Private + $Checks + $Reports + $Public)) {
    try {
        . $file.FullName
    }
    catch {
        Write-Error "Failed to load $($file.FullName): $_"
    }
}

# Export public functions
Export-ModuleMember -Function @(
    'Invoke-CISAzureBenchmark'
    'Get-CISControlList'
    'Export-CISReport'
)
