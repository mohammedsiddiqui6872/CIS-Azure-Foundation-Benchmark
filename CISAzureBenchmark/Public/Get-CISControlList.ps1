function Get-CISControlList {
    <#
    .SYNOPSIS
        Lists all CIS Azure Benchmark v5.0.0 controls with filtering options.

    .DESCRIPTION
        Returns the full list of 152 CIS controls with metadata. Useful for discovering
        available controls, filtering by section or assessment status, and planning scans.

    .PARAMETER Section
        Filter by section name or number.

    .PARAMETER AssessmentStatus
        Filter by assessment status: 'Automated', 'Manual', or 'All'.

    .PARAMETER ProfileLevel
        Filter by maximum profile level (1 or 2).

    .PARAMETER ControlId
        Get specific controls by ID.

    .PARAMETER Severity
        Filter by severity level.

    .EXAMPLE
        Get-CISControlList | Measure-Object
        # Returns 152

    .EXAMPLE
        Get-CISControlList -AssessmentStatus Automated
        # Returns all 79 automated controls

    .EXAMPLE
        Get-CISControlList -Section 'Identity Services' -Severity Critical,High
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$Section,

        [Parameter()]
        [ValidateSet('Automated', 'Manual', 'All')]
        [string]$AssessmentStatus = 'All',

        [Parameter()]
        [ValidateSet(1, 2)]
        [int]$ProfileLevel = 2,

        [Parameter()]
        [string[]]$ControlId,

        [Parameter()]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string[]]$Severity
    )

    $defPath = Join-Path (Join-Path (Join-Path $PSScriptRoot '..') 'Data') 'ControlDefinitions.psd1'
    if (-not (Test-Path $defPath)) {
        Write-Error "Control definitions file not found: $defPath"
        return
    }

    $definitions = Import-PowerShellDataFile -Path $defPath
    $controls = $definitions.Controls

    # Apply filters
    $controls = $controls | Where-Object { $_.ProfileLevel -le $ProfileLevel }

    if ($AssessmentStatus -ne 'All') {
        $controls = $controls | Where-Object { $_.AssessmentStatus -eq $AssessmentStatus }
    }

    if ($Section) {
        $controls = $controls | Where-Object {
            $ctrl = $_
            $Section | Where-Object {
                $ctrl.Section -like "*$_*" -or
                $ctrl.ControlId -like "$_*" -or
                $ctrl.Subsection -like "*$_*"
            }
        }
    }

    if ($ControlId) {
        $controls = $controls | Where-Object { $_.ControlId -in $ControlId }
    }

    if ($Severity) {
        $controls = $controls | Where-Object { $_.Severity -in $Severity }
    }

    # Return as clean objects
    $controls | ForEach-Object {
        [PSCustomObject]@{
            ControlId        = $_.ControlId
            Title            = $_.Title
            Section          = $_.Section
            Subsection       = $_.Subsection
            AssessmentStatus = $_.AssessmentStatus
            ProfileLevel     = $_.ProfileLevel
            Severity         = $_.Severity
            CheckPattern     = $_.CheckPattern
        }
    } | Sort-Object { [version]($_.ControlId -replace '[^\d.]', '' -replace '\.+$', '' -replace '^\.+', '') }
}
