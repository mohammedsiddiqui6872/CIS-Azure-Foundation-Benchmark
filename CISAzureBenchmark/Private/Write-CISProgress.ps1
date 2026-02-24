if (-not $script:CISProgressTimes) { $script:CISProgressTimes = [System.Collections.Generic.List[double]]::new() }
if (-not $script:CISProgressLastCheck) { $script:CISProgressLastCheck = $null }

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

    # Track timing for ETA estimation
    $now = [DateTime]::UtcNow
    if ($script:CISProgressLastCheck) {
        $elapsed = ($now - $script:CISProgressLastCheck).TotalSeconds
        $script:CISProgressTimes.Add($elapsed)
    }
    $script:CISProgressLastCheck = $now

    $eta = ''
    if ($script:CISProgressTimes.Count -ge 3 -and $Current -lt $Total) {
        $avgTime = ($script:CISProgressTimes | Measure-Object -Average).Average
        $remaining = ($Total - $Current) * $avgTime
        if ($remaining -ge 60) {
            $eta = " (~$([math]::Ceiling($remaining / 60)) min remaining)"
        } else {
            $eta = " (~$([math]::Ceiling($remaining))s remaining)"
        }
    }

    $progressParams = @{
        Activity = "CIS Azure Benchmark v5.0.0 - $Activity"
        Status   = "${Status}${eta}"
    }

    if ($PercentComplete -ge 0) {
        $progressParams.PercentComplete = $PercentComplete
    }

    Write-Progress @progressParams
}
