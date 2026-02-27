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

    # Single-pass counting instead of multiple Where-Object calls
    $total   = $Results.Count
    $pass    = 0
    $fail    = 0
    $warning = 0
    $info    = 0
    $error_  = 0
    foreach ($r in $Results) {
        switch ($r.Status) {
            'PASS'    { $pass++ }
            'FAIL'    { $fail++ }
            'WARNING' { $warning++ }
            'INFO'    { $info++ }
            'ERROR'   { $error_++ }
        }
    }

    # Exclude INFO, WARNING, and ERROR from the scoring denominator
    $scoreDenom = $total - $info - $warning - $error_
    $overallScore = if ($scoreDenom -gt 0) {
        [math]::Round(($pass / $scoreDenom) * 100, 1)
    } else { -1 }

    $report = [ordered]@{
        benchmarkVersion = "CIS Microsoft Azure Foundations Benchmark $(if ($script:CISBenchmarkVersion) { $script:CISBenchmarkVersion } else { 'v5.0.0' })"
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
            $sTotal = $_.Group.Count
            $sPass = 0; $sFail = 0; $sWarn = 0; $sInfo = 0; $sError = 0
            foreach ($item in $_.Group) {
                switch ($item.Status) {
                    'PASS'    { $sPass++ }
                    'FAIL'    { $sFail++ }
                    'WARNING' { $sWarn++ }
                    'INFO'    { $sInfo++ }
                    'ERROR'   { $sError++ }
                }
            }
            $sDenom = $sTotal - $sInfo - $sWarn - $sError
            [ordered]@{
                section    = $_.Name
                total      = $sTotal
                passed     = $sPass
                failed     = $sFail
                warning    = $sWarn
                info       = $sInfo
                error      = $sError
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
