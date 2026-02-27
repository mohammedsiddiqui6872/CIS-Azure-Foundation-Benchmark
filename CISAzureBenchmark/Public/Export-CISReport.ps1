function Export-CISReport {
    <#
    .SYNOPSIS
        Re-generates reports from a previously saved JSON scan result.

    .DESCRIPTION
        Takes a CIS benchmark JSON report file and generates HTML and/or CSV reports
        from it. Useful for regenerating reports without re-running the scan.

    .PARAMETER JsonPath
        Path to the previously saved JSON report file.

    .PARAMETER OutputDirectory
        Directory for generated reports.

    .PARAMETER OutputFormat
        Report format(s) to generate: 'HTML', 'CSV', or 'All'.

    .PARAMETER ReportName
        Base name for report files. Derived from JSON filename if not specified.

    .EXAMPLE
        Export-CISReport -JsonPath ./reports/CIS-Azure-v5.0.0_MySub_20260223.json

    .EXAMPLE
        Export-CISReport -JsonPath ./scan.json -OutputFormat HTML -OutputDirectory ./dashboards
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$JsonPath,

        [Parameter()]
        [string]$OutputDirectory,

        [Parameter()]
        [ValidateSet('HTML', 'CSV', 'SARIF', 'All')]
        [string[]]$OutputFormat = @('All'),

        [Parameter()]
        [string]$ReportName
    )

    if (-not (Test-Path $JsonPath)) {
        Write-Error "JSON file not found: $JsonPath"
        return
    }

    try {
        $jsonData = Get-Content -Path $JsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        Write-Error "Failed to parse JSON file '$JsonPath': $($_.Exception.Message)"
        return
    }

    if (-not $OutputDirectory) {
        $OutputDirectory = Split-Path $JsonPath -Parent
    }

    if (-not (Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    if (-not $ReportName) {
        $ReportName = [System.IO.Path]::GetFileNameWithoutExtension($JsonPath)
    }

    # Reconstruct metadata
    $metadata = @{
        SubscriptionName = $jsonData.subscriptionName
        SubscriptionId   = $jsonData.subscriptionId
        TenantId         = $jsonData.tenantId
        ScanTimestamp    = $jsonData.scanTimestamp
    }

    # Reconstruct results array
    $results = $jsonData.results | ForEach-Object {
        [PSCustomObject]@{
            PSTypeName       = 'CISBenchmarkResult'
            ControlId        = $_.controlId
            Title            = $_.title
            Status           = $_.status
            Severity         = $_.severity
            Section          = $_.section
            Subsection       = $_.subsection
            AssessmentStatus = $_.assessmentStatus
            ProfileLevel     = $_.profileLevel
            Description      = $_.description
            Details          = $_.details
            Remediation      = $_.remediation
            AffectedResources = if ($_.affectedResources) { @($_.affectedResources) } else { @() }
            TotalResources   = $_.totalResources
            PassedResources  = $_.passedResources
            FailedResources  = $_.failedResources
            References       = if ($_.references) { @($_.references) } else { @() }
            CISControls      = if ($_.cisControls) { @($_.cisControls) } else { @() }
            Timestamp        = $_.timestamp
        }
    }

    $formats = if ('All' -in $OutputFormat) { @('HTML', 'CSV', 'SARIF') } else { $OutputFormat }
    $reportPaths = @{}

    if ('HTML' -in $formats) {
        $htmlPath = Join-Path $OutputDirectory "$ReportName.html"
        Write-Host "  Generating HTML report..." -ForegroundColor Yellow
        $reportPaths.HTML = New-CISHtmlReport -Results $results -OutputPath $htmlPath -Metadata $metadata
        Write-Host "  HTML: $htmlPath" -ForegroundColor Green
    }

    if ('CSV' -in $formats) {
        $csvPath = Join-Path $OutputDirectory "$ReportName.csv"
        Write-Host "  Generating CSV report..." -ForegroundColor Yellow
        $reportPaths.CSV = New-CISCsvReport -Results $results -OutputPath $csvPath -Metadata $metadata
        Write-Host "  CSV:  $csvPath" -ForegroundColor Green
    }

    if ('SARIF' -in $formats) {
        $sarifPath = Join-Path $OutputDirectory "$ReportName.sarif"
        Write-Host "  Generating SARIF report..." -ForegroundColor Yellow
        $reportPaths.SARIF = New-CISSarifReport -Results $results -OutputPath $sarifPath -Metadata $metadata
        Write-Host "  SARIF: $sarifPath" -ForegroundColor Green
    }

    return $reportPaths
}
