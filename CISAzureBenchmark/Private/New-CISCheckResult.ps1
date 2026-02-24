function New-CISCheckResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ControlId,

        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [ValidateSet('PASS', 'FAIL', 'WARNING', 'INFO', 'ERROR')]
        [string]$Status,

        [Parameter()]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string]$Severity = 'Medium',

        [Parameter()]
        [string]$Section,

        [Parameter()]
        [string]$Subsection,

        [Parameter()]
        [ValidateSet('Automated', 'Manual')]
        [string]$AssessmentStatus = 'Automated',

        [Parameter()]
        [int]$ProfileLevel = 1,

        [Parameter()]
        [string]$Description,

        [Parameter()]
        [string]$Details,

        [Parameter()]
        [string]$Remediation,

        [Parameter()]
        [string[]]$AffectedResources = @(),

        [Parameter()]
        [int]$TotalResources = 0,

        [Parameter()]
        [int]$PassedResources = 0,

        [Parameter()]
        [int]$FailedResources = 0,

        [Parameter()]
        [string[]]$References = @(),

        [Parameter()]
        [string[]]$CISControls = @()
    )

    [PSCustomObject]@{
        PSTypeName       = 'CISBenchmarkResult'
        ControlId        = $ControlId
        Title            = $Title
        Status           = $Status
        Severity         = $Severity
        Section          = $Section
        Subsection       = $Subsection
        AssessmentStatus = $AssessmentStatus
        ProfileLevel     = $ProfileLevel
        Description      = $Description
        Details          = $Details
        Remediation      = $Remediation
        AffectedResources = $AffectedResources
        TotalResources   = $TotalResources
        PassedResources  = $PassedResources
        FailedResources  = $FailedResources
        References       = $References
        CISControls      = $CISControls
        Timestamp        = [DateTime]::UtcNow.ToString('o')
    }
}
