function New-CISHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter()]
        [hashtable]$Metadata = @{},

        [Parameter()]
        [hashtable]$MultiSubscriptionData = @{}
    )

    $templatePath = Join-Path (Join-Path (Join-Path $PSScriptRoot '..') 'Data') 'HtmlTemplate.html'
    if (-not (Test-Path $templatePath)) {
        Write-Error "HTML template not found at: $templatePath"
        return
    }

    $template = Get-Content -Path $templatePath -Raw -Encoding UTF8

    # Calculate statistics for primary/combined results — single-pass counting
    $total = $Results.Count
    $pass = 0; $fail = 0; $warning = 0; $info = 0; $error_ = 0
    foreach ($r in $Results) {
        switch ($r.Status) {
            'PASS'    { $pass++ }
            'FAIL'    { $fail++ }
            'WARNING' { $warning++ }
            'INFO'    { $info++ }
            'ERROR'   { $error_++ }
        }
    }

    # Score excludes INFO, WARNING, and ERROR from denominator
    $scoreDenom = $total - $info - $warning - $error_
    $overallScore = if ($scoreDenom -gt 0) {
        [math]::Round(($pass / $scoreDenom) * 100, 1)
    } else { -1 }

    # Helper to convert results array to JSON-friendly ordered hashtables
    function ConvertTo-ResultPayload {
        param([PSCustomObject[]]$ResultSet)
        $ResultSet | ForEach-Object {
            [ordered]@{
                ControlId        = $_.ControlId
                Title            = $_.Title
                Status           = $_.Status
                Severity         = $_.Severity
                Section          = $_.Section
                Subsection       = $_.Subsection
                AssessmentStatus = $_.AssessmentStatus
                ProfileLevel     = $_.ProfileLevel
                Description      = $_.Description
                Details          = $_.Details
                Remediation      = $_.Remediation
                AffectedResources = $_.AffectedResources
                TotalResources   = $_.TotalResources
                PassedResources  = $_.PassedResources
                FailedResources  = $_.FailedResources
                References       = $_.References
                CISControls      = $_.CISControls
                Timestamp        = $_.Timestamp
            }
        }
    }

    # Convert main results to JSON
    $resultArray = @(ConvertTo-ResultPayload -ResultSet $Results)
    $jsonPayload = ConvertTo-Json -InputObject @($resultArray) -Depth 10 -Compress

    # Build multi-subscription data JSON
    $multiSubJson = 'null'
    if ($MultiSubscriptionData -and $MultiSubscriptionData.Count -gt 0) {
        # Build multi-sub JSON safely using ConvertTo-Json
        $multiSubObj = [ordered]@{}
        foreach ($subId in $MultiSubscriptionData.Keys) {
            $subData = $MultiSubscriptionData[$subId]
            $subResultsArray = @(ConvertTo-ResultPayload -ResultSet $subData.Results)
            $multiSubObj[$subId] = [ordered]@{
                name     = $subData.Name
                id       = $subId
                tenantId = $subData.TenantId
                results  = $subResultsArray
            }
        }
        $multiSubJson = $multiSubObj | ConvertTo-Json -Depth 12 -Compress
    }

    # Sanitize payloads to prevent script injection
    $jsonPayload = $jsonPayload -replace '</', '<\/'
    $multiSubJson = $multiSubJson -replace '</', '<\/'

    # Helper for HTML encoding that works on both PS 5.1 and PS 7+
    function Encode-HtmlSafe {
        param([string]$Value)
        if (-not $Value) { return '' }
        try {
            return [System.Web.HttpUtility]::HtmlEncode($Value)
        }
        catch {
            # Fallback for PS 5.1 if System.Web is not loaded
            try {
                return [System.Net.WebUtility]::HtmlEncode($Value)
            }
            catch {
                # Manual fallback
                return $Value -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'",'&#39;'
            }
        }
    }

    # Replace tokens — HTML-encode ALL user-facing values to prevent XSS
    $html = $template
    $bmkVersion = if ($script:CISBenchmarkVersion) { $script:CISBenchmarkVersion } else { 'v5.0.0' }
    $html = $html -replace '\{\{BENCHMARK_VERSION\}\}', $bmkVersion
    $scanTs = if ($Metadata.ScanTimestamp) { $Metadata.ScanTimestamp } else { [DateTime]::UtcNow.ToString('o') }
    $subName = if ($Metadata.SubscriptionName) { $Metadata.SubscriptionName } else { 'N/A' }
    $subId = if ($Metadata.SubscriptionId) { $Metadata.SubscriptionId } else { 'N/A' }
    $tenId = if ($Metadata.TenantId) { $Metadata.TenantId } else { 'N/A' }
    $html = $html -replace '\{\{SCAN_TIMESTAMP\}\}', (Encode-HtmlSafe $scanTs)
    $html = $html -replace '\{\{SUBSCRIPTION_NAME\}\}', (Encode-HtmlSafe $subName)
    $html = $html -replace '\{\{SUBSCRIPTION_ID\}\}', (Encode-HtmlSafe $subId)
    $html = $html -replace '\{\{TENANT_ID\}\}', (Encode-HtmlSafe $tenId)
    $scannedBy = if ($Metadata.ScannedBy) { $Metadata.ScannedBy } else { 'N/A' }
    $html = $html -replace '\{\{SCANNED_BY\}\}', (Encode-HtmlSafe $scannedBy)
    $html = $html -replace '\{\{OVERALL_SCORE\}\}', $overallScore.ToString()
    $html = $html -replace '\{\{TOTAL_CONTROLS\}\}', $total.ToString()
    $html = $html -replace '\{\{PASS_COUNT\}\}', $pass.ToString()
    $html = $html -replace '\{\{FAIL_COUNT\}\}', $fail.ToString()
    $html = $html -replace '\{\{WARNING_COUNT\}\}', $warning.ToString()
    $html = $html -replace '\{\{INFO_COUNT\}\}', $info.ToString()
    $html = $html -replace '\{\{ERROR_COUNT\}\}', $error_.ToString()
    $html = $html -replace '\{\{REPORT_DATA\}\}', $jsonPayload
    $html = $html -replace '\{\{MULTI_SUB_DATA\}\}', $multiSubJson

    # Write output
    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Verbose "HTML report written to: $OutputPath"

    return $OutputPath
}
