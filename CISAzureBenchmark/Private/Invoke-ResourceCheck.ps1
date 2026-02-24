function Invoke-ResourceCheck {
    <#
    .SYNOPSIS
        Reusable helper that evaluates a collection of resources against a check scriptblock.
    .DESCRIPTION
        Encapsulates the common pattern of iterating resources, collecting pass/fail results,
        and returning a standardized CISBenchmarkResult. Eliminates boilerplate in custom checks.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter()]
        [object[]]$Resources = @(),

        [Parameter(Mandatory)]
        [string]$ResourceTypeName,

        [Parameter(Mandatory)]
        [scriptblock]$CheckScript,

        [Parameter()]
        [switch]$FailOnEmpty
    )

    try {
        if ($null -eq $Resources -or $Resources.Count -eq 0) {
            if ($FailOnEmpty) {
                return New-CISCheckResult `
                    -ControlId $ControlDef.ControlId `
                    -Title $ControlDef.Title `
                    -Status 'FAIL' `
                    -Details "No $ResourceTypeName found. This resource is required." `
                    -AffectedResources @("No $ResourceTypeName deployed") `
                    -TotalResources 0 -PassedResources 0 -FailedResources 1
            }
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No $ResourceTypeName found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $totalCount  = $Resources.Count
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        foreach ($resource in $Resources) {
            # CheckScript receives $resource and should return:
            #   $null or empty string = PASS
            #   non-empty string = FAIL (the string is the failure reason)
            $failureReason = & $CheckScript $resource
            if ($failureReason) {
                $failedList.Add([string]$failureReason)
            }
            else {
                $passedCount++
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "$failedCount of $totalCount $ResourceTypeName do not meet requirements: $($failedList -join '; ')"
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details $details `
                -AffectedResources $failedList.ToArray() `
                -TotalResources $totalCount `
                -PassedResources $passedCount `
                -FailedResources $failedCount
        }

        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'PASS' `
            -Details "All $totalCount $ResourceTypeName meet requirements." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking ${ResourceTypeName}: $($_.Exception.Message)"
    }
}
