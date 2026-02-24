function New-CISJsonReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter()]
        [hashtable]$Metadata = @{}
    )

    $total   = $Results.Count
    $pass    = ($Results | Where-Object Status -eq 'PASS').Count
    $fail    = ($Results | Where-Object Status -eq 'FAIL').Count
    $warning = ($Results | Where-Object Status -eq 'WARNING').Count
    $info    = ($Results | Where-Object Status -eq 'INFO').Count
    $error_  = ($Results | Where-Object Status -eq 'ERROR').Count

    $scoreDenom = $total - $info - $warning
    $overallScore = if ($scoreDenom -gt 0) {
        [math]::Round(($pass / $scoreDenom) * 100, 1)
    } else { -1 }

    $report = [ordered]@{
        benchmarkVersion = 'CIS Microsoft Azure Foundations Benchmark v5.0.0'
        scanTimestamp    = if ($Metadata.ScanTimestamp) { $Metadata.ScanTimestamp } else { [DateTime]::UtcNow.ToString('o') }
        subscriptionName = if ($Metadata.SubscriptionName) { $Metadata.SubscriptionName } else { 'N/A' }
        subscriptionId   = if ($Metadata.SubscriptionId) { $Metadata.SubscriptionId } else { 'N/A' }
        tenantId         = if ($Metadata.TenantId) { $Metadata.TenantId } else { 'N/A' }
        summary          = [ordered]@{
            overallScore   = $overallScore
            totalControls  = $total
            passed         = $pass
            failed         = $fail
            warning        = $warning
            info           = $info
            error          = $error_
        }
        sectionBreakdown = ($Results | Group-Object Section | ForEach-Object {
            $sPass = ($_.Group | Where-Object Status -eq 'PASS').Count
            $sTotal = $_.Group.Count
            $sInfo = ($_.Group | Where-Object Status -eq 'INFO').Count
            $sWarn = ($_.Group | Where-Object Status -eq 'WARNING').Count
            $sDenom = $sTotal - $sInfo - $sWarn
            [ordered]@{
                section    = $_.Name
                total      = $sTotal
                passed     = $sPass
                failed     = ($_.Group | Where-Object Status -eq 'FAIL').Count
                warning    = ($_.Group | Where-Object Status -eq 'WARNING').Count
                info       = $sInfo
                error      = ($_.Group | Where-Object Status -eq 'ERROR').Count
                score      = if ($sDenom -gt 0) { [math]::Round(($sPass / $sDenom) * 100, 1) } else { -1 }
            }
        })
        results = ($Results | ForEach-Object {
            [ordered]@{
                controlId        = $_.ControlId
                title            = $_.Title
                status           = $_.Status
                severity         = $_.Severity
                section          = $_.Section
                subsection       = $_.Subsection
                assessmentStatus = $_.AssessmentStatus
                profileLevel     = $_.ProfileLevel
                description      = $_.Description
                details          = $_.Details
                remediation      = $_.Remediation
                affectedResources = $_.AffectedResources
                totalResources   = $_.TotalResources
                passedResources  = $_.PassedResources
                failedResources  = $_.FailedResources
                references       = $_.References
                cisControls      = $_.CISControls
                timestamp        = $_.Timestamp
            }
        })
    }

    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Verbose "JSON report written to: $OutputPath"

    return $OutputPath
}
