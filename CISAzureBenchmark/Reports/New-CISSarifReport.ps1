function New-CISSarifReport {
    <#
    .SYNOPSIS
        Generates a SARIF v2.1.0 report from CIS benchmark results.
    .DESCRIPTION
        Creates a Static Analysis Results Interchange Format (SARIF) report
        compatible with GitHub Code Scanning, Azure DevOps, and other security tools.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter()]
        [hashtable]$Metadata = @{}
    )

    # Map CIS status to SARIF level
    $levelMap = @{
        'FAIL'    = 'error'
        'WARNING' = 'warning'
        'ERROR'   = 'error'
        'INFO'    = 'note'
        'PASS'    = 'none'
    }

    # Map CIS severity to SARIF security-severity
    $severityScore = @{
        'Critical'      = '9.5'
        'High'          = '7.5'
        'Medium'        = '5.5'
        'Low'           = '3.5'
        'Informational' = '1.0'
    }

    # Build rules array
    $rules = [System.Collections.Generic.List[hashtable]]::new()
    $ruleIndex = @{}
    $idx = 0

    foreach ($r in $Results) {
        if (-not $ruleIndex.ContainsKey($r.ControlId)) {
            $ruleIndex[$r.ControlId] = $idx
            $idx++
            $rule = [ordered]@{
                id               = "CIS-$($r.ControlId)"
                name             = ($r.Title -replace '[^\w\s-]', '').Trim()
                shortDescription = [ordered]@{ text = $r.Title }
                fullDescription  = [ordered]@{ text = if ($r.Description) { $r.Description } else { $r.Title } }
                helpUri          = if ($r.References -and $r.References.Count -gt 0) { $r.References[0] } else { 'https://www.cisecurity.org/benchmark/azure' }
                properties       = [ordered]@{
                    tags              = @('security', 'compliance', 'CIS', "CIS-$($r.Section)")
                    'security-severity' = if ($severityScore[$r.Severity]) { $severityScore[$r.Severity] } else { '5.5' }
                    precision         = if ($r.AssessmentStatus -eq 'Automated') { 'high' } else { 'low' }
                }
            }
            if ($r.Remediation) {
                $rule.help = [ordered]@{
                    text     = $r.Remediation
                    markdown = "**Remediation:** $($r.Remediation)"
                }
            }
            $rules.Add($rule)
        }
    }

    # Build results array (only non-PASS results)
    $sarifResults = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($r in $Results) {
        if ($r.Status -eq 'PASS') { continue }

        $sarifResult = [ordered]@{
            ruleId    = "CIS-$($r.ControlId)"
            ruleIndex = $ruleIndex[$r.ControlId]
            level     = if ($levelMap[$r.Status]) { $levelMap[$r.Status] } else { 'warning' }
            message   = [ordered]@{
                text = if ($r.Details) { $r.Details } else { "$($r.Title): $($r.Status)" }
            }
            properties = [ordered]@{
                controlId        = $r.ControlId
                section          = $r.Section
                subsection       = $r.Subsection
                assessmentStatus = $r.AssessmentStatus
                profileLevel     = $r.ProfileLevel
                severity         = $r.Severity
                totalResources   = $r.TotalResources
                passedResources  = $r.PassedResources
                failedResources  = $r.FailedResources
            }
        }

        if ($r.AffectedResources -and $r.AffectedResources.Count -gt 0) {
            $locations = [System.Collections.Generic.List[hashtable]]::new()
            foreach ($res in $r.AffectedResources) {
                $locations.Add([ordered]@{
                    physicalLocation = [ordered]@{
                        artifactLocation = [ordered]@{
                            uri = "azure://subscription/$(if ($Metadata.SubscriptionId) { $Metadata.SubscriptionId } else { 'unknown' })"
                        }
                    }
                    message = [ordered]@{ text = $res }
                })
            }
            $sarifResult.locations = $locations.ToArray()
        }

        $sarifResults.Add($sarifResult)
    }

    # Build SARIF document
    $sarif = [ordered]@{
        '$schema' = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json'
        version   = '2.1.0'
        runs      = @(
            [ordered]@{
                tool = [ordered]@{
                    driver = [ordered]@{
                        name            = 'CIS Azure Benchmark'
                        version         = '5.0.0'
                        semanticVersion = '5.0.0'
                        informationUri  = 'https://github.com/mohammedsiddiqui6872/CIS-Azure-Foundation-Benchmark'
                        rules           = $rules.ToArray()
                    }
                }
                results    = $sarifResults.ToArray()
                invocations = @(
                    [ordered]@{
                        executionSuccessful = $true
                        startTimeUtc        = if ($Metadata.ScanTimestamp) { $Metadata.ScanTimestamp } else { [DateTime]::UtcNow.ToString('o') }
                    }
                )
                properties = [ordered]@{
                    subscriptionName = if ($Metadata.SubscriptionName) { $Metadata.SubscriptionName } else { 'N/A' }
                    subscriptionId   = if ($Metadata.SubscriptionId) { $Metadata.SubscriptionId } else { 'N/A' }
                    tenantId         = if ($Metadata.TenantId) { $Metadata.TenantId } else { 'N/A' }
                    benchmarkVersion = 'CIS Microsoft Azure Foundations Benchmark v5.0.0'
                }
            }
        )
    }

    $sarifJson = $sarif | ConvertTo-Json -Depth 20 -Compress:$false
    $sarifJson | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Verbose "SARIF report written to: $OutputPath"

    return $OutputPath
}
