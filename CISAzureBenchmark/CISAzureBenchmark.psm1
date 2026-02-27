#Requires -Version 5.1
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

# Load benchmark version from ControlDefinitions and module version from manifest
$script:CISBenchmarkVersion = 'v5.0.0'  # fallback
$script:CISModuleVersion = '5.1.0'      # fallback
try {
    $defPath = Join-Path (Join-Path $ModuleRoot 'Data') 'ControlDefinitions.psd1'
    if (Test-Path $defPath) {
        $defs = Import-PowerShellDataFile -Path $defPath
        if ($defs.BenchmarkVersion) { $script:CISBenchmarkVersion = $defs.BenchmarkVersion }
    }
} catch { }
try {
    $manifestPath = Join-Path $ModuleRoot 'CISAzureBenchmark.psd1'
    if (Test-Path $manifestPath) {
        $manifest = Import-PowerShellDataFile -Path $manifestPath
        if ($manifest.ModuleVersion) { $script:CISModuleVersion = $manifest.ModuleVersion }
    }
} catch { }

# Ensure System.Web.HttpUtility is available (used for HTML encoding in reports)
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

function Merge-Hashtable {
    <#
    .SYNOPSIS
        Recursively merges $Source into $Target. Nested hashtables are merged; other values are overwritten.
    #>
    param(
        [hashtable]$Target,
        [hashtable]$Source
    )
    foreach ($key in $Source.Keys) {
        if ($Target.ContainsKey($key) -and $Target[$key] -is [hashtable] -and $Source[$key] -is [hashtable]) {
            Merge-Hashtable -Target $Target[$key] -Source $Source[$key]
        } else {
            $Target[$key] = $Source[$key]
        }
    }
}

function Set-CISConfigOverride {
    <#
    .SYNOPSIS
        Deep-merges user config overrides into the module configuration.
    .DESCRIPTION
        Nested hashtable values are recursively merged so users can override individual
        keys without losing other defaults at the same level.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ConfigPath)

    if (-not (Test-Path $ConfigPath)) {
        Write-Warning "Config file not found: $ConfigPath. Using defaults."
        return
    }
    $userConfig = Import-PowerShellDataFile -Path $ConfigPath
    Merge-Hashtable -Target $script:CISConfig -Source $userConfig
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
    'Disconnect-CISAzureBenchmark'
    'Invoke-CISAzureBenchmark'
    'Get-CISControlList'
    'Export-CISReport'
    'Compare-CISBenchmarkResults'
    'Export-CISRemediationScript'
)
