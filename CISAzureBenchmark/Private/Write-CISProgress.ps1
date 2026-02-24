function Write-CISProgress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Activity,

        [Parameter()]
        [string]$Status = 'Processing...',

        [Parameter()]
        [int]$PercentComplete = -1,

        [Parameter()]
        [int]$Current = 0,

        [Parameter()]
        [int]$Total = 0
    )

    if ($Total -gt 0 -and $Current -gt 0) {
        $PercentComplete = [math]::Min(100, [math]::Round(($Current / $Total) * 100))
        $Status = "[$Current/$Total] $Status"
    }

    $progressParams = @{
        Activity = "CIS Azure Benchmark v5.0.0 - $Activity"
        Status   = $Status
    }

    if ($PercentComplete -ge 0) {
        $progressParams.PercentComplete = $PercentComplete
    }

    Write-Progress @progressParams
}
