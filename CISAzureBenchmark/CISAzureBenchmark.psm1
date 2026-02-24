# CIS Microsoft Azure Foundations Benchmark v5.0.0 - Compliance Checker Module
# Covers all 155 controls (93 Automated + 62 Manual)

$ModuleRoot = $PSScriptRoot

# Load default module configuration
$script:CISConfigPath = Join-Path (Join-Path $ModuleRoot 'Data') 'ModuleConfig.psd1'
$script:CISConfig = if (Test-Path $script:CISConfigPath) {
    Import-PowerShellDataFile -Path $script:CISConfigPath
} else {
    @{}
}

function Set-CISConfigOverride {
    <#
    .SYNOPSIS
        Merges user config overrides into the module configuration.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ConfigPath)

    if (-not (Test-Path $ConfigPath)) {
        Write-Warning "Config file not found: $ConfigPath. Using defaults."
        return
    }
    $userConfig = Import-PowerShellDataFile -Path $ConfigPath
    foreach ($key in $userConfig.Keys) {
        $script:CISConfig[$key] = $userConfig[$key]
    }
}

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
    'Connect-CISAzureBenchmark'
    'Invoke-CISAzureBenchmark'
    'Get-CISControlList'
    'Export-CISReport'
    'Compare-CISBenchmarkResults'
    'Export-CISRemediationScript'
)
