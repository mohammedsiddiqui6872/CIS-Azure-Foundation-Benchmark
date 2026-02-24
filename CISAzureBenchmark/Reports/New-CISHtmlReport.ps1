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

    # Calculate statistics for primary/combined results
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

    # Replace tokens
    $html = $template
    $html = $html -replace '\{\{BENCHMARK_VERSION\}\}', 'v5.0.0'
    $scanTs = if ($Metadata.ScanTimestamp) { $Metadata.ScanTimestamp } else { [DateTime]::UtcNow.ToString('o') }
    $subName = if ($Metadata.SubscriptionName) { $Metadata.SubscriptionName } else { 'N/A' }
    $subId = if ($Metadata.SubscriptionId) { $Metadata.SubscriptionId } else { 'N/A' }
    $tenId = if ($Metadata.TenantId) { $Metadata.TenantId } else { 'N/A' }
    $html = $html -replace '\{\{SCAN_TIMESTAMP\}\}', $scanTs
    $html = $html -replace '\{\{SUBSCRIPTION_NAME\}\}', [System.Web.HttpUtility]::HtmlEncode($subName)
    $html = $html -replace '\{\{SUBSCRIPTION_ID\}\}', $subId
    $html = $html -replace '\{\{TENANT_ID\}\}', $tenId
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
