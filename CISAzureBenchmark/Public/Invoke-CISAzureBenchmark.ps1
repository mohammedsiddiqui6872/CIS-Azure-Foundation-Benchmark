function Invoke-CISAzureBenchmark {
    <#
    .SYNOPSIS
        Runs the CIS Microsoft Azure Foundations Benchmark v5.0.0 compliance checks.

    .DESCRIPTION
        Evaluates one or more Azure subscriptions against all 155 CIS controls (93 Automated + 62 Manual)
        from CIS Microsoft Azure Foundations Benchmark v5.0.0. Generates HTML dashboard, JSON,
        and CSV reports showing compliance status.

    .PARAMETER Section
        Filter by section(s). Examples: '5', '7', '8.1', 'Identity Services'

    .PARAMETER AssessmentStatus
        Filter by assessment status: 'Automated', 'Manual', or 'All' (default).

    .PARAMETER ProfileLevel
        Maximum profile level to include. Level 2 (default) includes both Level 1 and Level 2.

    .PARAMETER ControlId
        Run specific controls by ID. Examples: '7.1', '8.3.5', '9.3.8'

    .PARAMETER ExcludeControlId
        Exclude specific controls by ID.

    .PARAMETER OutputDirectory
        Directory for report output. Defaults to current directory.

    .PARAMETER OutputFormat
        Report format(s): 'HTML', 'JSON', 'CSV', or 'All' (default).

    .PARAMETER ReportName
        Base name for report files. Auto-generated if not specified.

    .PARAMETER SubscriptionId
        Target subscription. Uses current context if not specified.

    .PARAMETER AllSubscriptions
        Scan all available subscriptions and combine results into a single HTML report
        with a subscription switcher dropdown.

    .PARAMETER SkipModuleCheck
        Skip Azure module validation.

    .EXAMPLE
        Invoke-CISAzureBenchmark -OutputDirectory ./reports

    .EXAMPLE
        Invoke-CISAzureBenchmark -AllSubscriptions -OutputDirectory ./reports

    .EXAMPLE
        Invoke-CISAzureBenchmark -Section '7','8' -AssessmentStatus Automated

    .EXAMPLE
        Invoke-CISAzureBenchmark -ProfileLevel 1 -OutputFormat HTML
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$Section,

        [Parameter()]
        [ValidateSet('Automated', 'Manual', 'All')]
        [string]$AssessmentStatus = 'All',

        [Parameter()]
        [ValidateSet(1, 2)]
        [int]$ProfileLevel = 2,

        [Parameter()]
        [string[]]$ControlId,

        [Parameter()]
        [string[]]$ExcludeControlId,

        [Parameter()]
        [string]$OutputDirectory = '.',

        [Parameter()]
        [ValidateSet('HTML', 'JSON', 'CSV', 'All')]
        [string[]]$OutputFormat = @('All'),

        [Parameter()]
        [string]$ReportName,

        [Parameter()]
        [string]$SubscriptionId,

        [Parameter()]
        [switch]$AllSubscriptions,

        [Parameter()]
        [switch]$SkipModuleCheck
    )

    $ErrorActionPreference = 'Continue'
    $startTime = Get-Date

    # Banner
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "  CIS Microsoft Azure Foundations Benchmark v5.0.0" -ForegroundColor Cyan
    Write-Host "  Compliance Checker" -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""

    # ----------------------------------------------------------------
    # 1. Load control definitions
    # ----------------------------------------------------------------
    $defPath = Join-Path $PSScriptRoot '..' 'Data' 'ControlDefinitions.psd1'
    if (-not (Test-Path $defPath)) {
        Write-Error "Control definitions file not found: $defPath"
        return
    }

    $definitions = Import-PowerShellDataFile -Path $defPath
    $allControls = $definitions.Controls
    Write-Host "  Loaded $($allControls.Count) control definitions" -ForegroundColor Green

    # ----------------------------------------------------------------
    # 2. Filter controls
    # ----------------------------------------------------------------
    $controls = $allControls

    $controls = $controls | Where-Object { $_.ProfileLevel -le $ProfileLevel }

    if ($AssessmentStatus -ne 'All') {
        $controls = $controls | Where-Object { $_.AssessmentStatus -eq $AssessmentStatus }
    }

    if ($Section) {
        $controls = $controls | Where-Object {
            $ctrl = $_
            $Section | Where-Object {
                $ctrl.Section -like "*$_*" -or
                $ctrl.ControlId -like "$_*" -or
                $ctrl.Subsection -like "*$_*"
            }
        }
    }

    if ($ControlId) {
        $controls = $controls | Where-Object { $_.ControlId -in $ControlId }
    }

    if ($ExcludeControlId) {
        $controls = $controls | Where-Object { $_.ControlId -notin $ExcludeControlId }
    }

    $automatedCount = ($controls | Where-Object { $_.AssessmentStatus -eq 'Automated' }).Count
    $manualCount = ($controls | Where-Object { $_.AssessmentStatus -eq 'Manual' }).Count

    Write-Host "  Running $($controls.Count) checks ($automatedCount automated, $manualCount manual)" -ForegroundColor Yellow
    Write-Host ""

    if ($controls.Count -eq 0) {
        Write-Warning "No controls match the specified filters."
        return
    }

    # ----------------------------------------------------------------
    # 3. Determine subscriptions to scan
    # ----------------------------------------------------------------
    $subscriptionsToScan = @()

    if ($AllSubscriptions) {
        $subscriptionsToScan = @(Get-AzSubscription -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq 'Enabled' })
        if ($subscriptionsToScan.Count -eq 0) {
            Write-Error "No enabled subscriptions found."
            return
        }
        Write-Host "  Scanning $($subscriptionsToScan.Count) subscription(s):" -ForegroundColor Cyan
        foreach ($sub in $subscriptionsToScan) {
            Write-Host "    - $($sub.Name) ($($sub.Id))" -ForegroundColor White
        }
        Write-Host ""
    } else {
        # Single subscription mode - just a placeholder
        $subscriptionsToScan = @($null)
    }

    # ----------------------------------------------------------------
    # 4. Run scans (single or multi-subscription)
    # ----------------------------------------------------------------
    $multiSubData = @{}
    $combinedResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $primaryMetadata = $null
    $subIndex = 0

    foreach ($targetSub in $subscriptionsToScan) {
        $subIndex++

        # Switch subscription context if multi-sub mode
        $currentSubId = $SubscriptionId
        if ($AllSubscriptions -and $targetSub) {
            $currentSubId = $targetSub.Id
            Write-Host "  [$subIndex/$($subscriptionsToScan.Count)] Switching to: $($targetSub.Name)" -ForegroundColor Yellow
            Set-AzContext -SubscriptionId $targetSub.Id -ErrorAction SilentlyContinue | Out-Null
        }

        # Initialize environment
        Write-CISProgress -Activity "Initializing" -Status "Validating environment..."

        $envInfo = Initialize-CISEnvironment `
            -SubscriptionId $currentSubId `
            -SkipModuleCheck:$SkipModuleCheck `
            -ControlsToRun $controls

        if (-not $envInfo.IsValid) {
            if ($AllSubscriptions) {
                Write-Warning "Skipping subscription $currentSubId - initialization failed"
                foreach ($err in $envInfo.Errors) { Write-Warning "  $err" }
                continue
            } else {
                foreach ($err in $envInfo.Errors) { Write-Error $err }
                return
            }
        }

        foreach ($warn in $envInfo.Warnings) { Write-Warning $warn }

        if (-not $primaryMetadata) {
            $primaryMetadata = @{
                SubscriptionName = $envInfo.SubscriptionName
                SubscriptionId   = $envInfo.SubscriptionId
                TenantId         = $envInfo.TenantId
                ScanTimestamp    = $envInfo.ScanTimestamp
            }
        }

        Write-Host "  Subscription: $($envInfo.SubscriptionName) ($($envInfo.SubscriptionId))" -ForegroundColor Cyan
        Write-Host "  Tenant:       $($envInfo.TenantId)" -ForegroundColor Cyan
        Write-Host ""

        # Pre-fetch resources
        Write-Host "  Pre-fetching Azure resources..." -ForegroundColor Yellow
        $resourceCache = Initialize-CISResourceCache -ControlsToRun $controls
        Write-Host "  Resource cache ready" -ForegroundColor Green
        Write-Host ""

        # Execute checks
        Write-Host "  Running compliance checks..." -ForegroundColor Yellow
        $subResults = [System.Collections.Generic.List[PSCustomObject]]::new()
        $checkCount = 0

        foreach ($ctrl in $controls) {
            $checkCount++
            $prefix = if ($AllSubscriptions) { "[$subIndex/$($subscriptionsToScan.Count)] " } else { "" }
            Write-CISProgress -Activity "${prefix}Running checks" `
                -Status "$($ctrl.ControlId) - $($ctrl.Title)" `
                -Current $checkCount -Total $controls.Count

            $result = Invoke-CISCheckSafely `
                -ControlDef $ctrl `
                -ResourceCache $resourceCache `
                -EnvironmentInfo $envInfo

            if ($result) {
                $subResults.Add($result)
                $combinedResults.Add($result)
            }
        }

        Write-Progress -Activity "CIS Azure Benchmark v5.0.0" -Completed

        # Store per-subscription data for multi-sub HTML
        if ($AllSubscriptions -and $targetSub) {
            $multiSubData[$envInfo.SubscriptionId] = @{
                Name     = $envInfo.SubscriptionName
                TenantId = $envInfo.TenantId
                Results  = $subResults.ToArray()
            }

            # Per-subscription summary
            $subPass = ($subResults | Where-Object Status -eq 'PASS').Count
            $subFail = ($subResults | Where-Object Status -eq 'FAIL').Count
            $subInfo = ($subResults | Where-Object Status -eq 'INFO').Count
            $subWarn = ($subResults | Where-Object Status -eq 'WARNING').Count
            $subError = ($subResults | Where-Object Status -eq 'ERROR').Count
            $subDenom = $subResults.Count - $subInfo - $subWarn
            $subScore = if ($subDenom -gt 0) { [math]::Round(($subPass / $subDenom) * 100, 1) } else { 0 }
            Write-Host ""
            Write-Host "  [$($envInfo.SubscriptionName)] Score: $subScore% | Pass: $subPass | Fail: $subFail | Error: $subError" -ForegroundColor $(if ($subScore -ge 80) { 'Green' } elseif ($subScore -ge 50) { 'Yellow' } else { 'Red' })
            Write-Host ""
        }
    }

    # Use combined results for everything from here
    $allResults = $combinedResults

    # ----------------------------------------------------------------
    # 5. Summary
    # ----------------------------------------------------------------
    $passCount    = ($allResults | Where-Object Status -eq 'PASS').Count
    $failCount    = ($allResults | Where-Object Status -eq 'FAIL').Count
    $warningCount = ($allResults | Where-Object Status -eq 'WARNING').Count
    $infoCount    = ($allResults | Where-Object Status -eq 'INFO').Count
    $errorCount   = ($allResults | Where-Object Status -eq 'ERROR').Count

    # Score excludes INFO (manual checks) and WARNING (indeterminate) from denominator
    $scoreDenom = $allResults.Count - $infoCount - $warningCount
    $score = if ($scoreDenom -gt 0) { [math]::Round(($passCount / $scoreDenom) * 100, 1) } else { 0 }

    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "  RESULTS SUMMARY$(if ($AllSubscriptions) { " (All $($multiSubData.Count) Subscriptions Combined)" })" -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "  Automated Checks Score: $score%" -ForegroundColor $(if ($score -ge 80) { 'Green' } elseif ($score -ge 50) { 'Yellow' } else { 'Red' })
    Write-Host "  (Based on $scoreDenom evaluated controls, excludes $infoCount manual + $warningCount indeterminate)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  PASS:    $passCount" -ForegroundColor Green
    Write-Host "  FAIL:    $failCount" -ForegroundColor Red
    Write-Host "  WARNING: $warningCount (Indeterminate)" -ForegroundColor Yellow
    Write-Host "  INFO:    $infoCount (Manual checks - require human review)" -ForegroundColor Blue
    Write-Host "  ERROR:   $errorCount" -ForegroundColor Gray
    Write-Host "  Total:   $($allResults.Count)" -ForegroundColor White
    Write-Host ""

    # ----------------------------------------------------------------
    # 6. Generate reports
    # ----------------------------------------------------------------
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    $metadata = $primaryMetadata ?? @{
        SubscriptionName = 'Unknown'
        SubscriptionId   = 'Unknown'
        TenantId         = 'Unknown'
        ScanTimestamp    = [DateTime]::UtcNow.ToString('o')
    }

    if ($AllSubscriptions) {
        $metadata.SubscriptionName = "All Subscriptions ($($multiSubData.Count))"
    }

    if (-not $ReportName) {
        $safeSub = if ($AllSubscriptions) { "AllSubscriptions" } else { ($metadata.SubscriptionName ?? 'Unknown') -replace '[^\w\-]', '_' }
        $dateStamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $ReportName = "CIS-Azure-v5.0.0_${safeSub}_${dateStamp}"
    }

    $formats = if ('All' -in $OutputFormat) { @('HTML', 'JSON', 'CSV') } else { $OutputFormat }

    $reportPaths = @{}

    if ('HTML' -in $formats) {
        $htmlPath = Join-Path $OutputDirectory "$ReportName.html"
        Write-Host "  Generating HTML report..." -ForegroundColor Yellow
        $htmlParams = @{
            Results    = $allResults
            OutputPath = $htmlPath
            Metadata   = $metadata
        }
        if ($multiSubData.Count -gt 0) {
            $htmlParams.MultiSubscriptionData = $multiSubData
        }
        $reportPaths.HTML = New-CISHtmlReport @htmlParams
        Write-Host "  HTML: $htmlPath" -ForegroundColor Green
    }

    if ('JSON' -in $formats) {
        $jsonPath = Join-Path $OutputDirectory "$ReportName.json"
        Write-Host "  Generating JSON report..." -ForegroundColor Yellow
        $reportPaths.JSON = New-CISJsonReport -Results $allResults -OutputPath $jsonPath -Metadata $metadata
        Write-Host "  JSON: $jsonPath" -ForegroundColor Green
    }

    if ('CSV' -in $formats) {
        $csvPath = Join-Path $OutputDirectory "$ReportName.csv"
        Write-Host "  Generating CSV report..." -ForegroundColor Yellow
        $reportPaths.CSV = New-CISCsvReport -Results $allResults -OutputPath $csvPath -Metadata $metadata
        Write-Host "  CSV:  $csvPath" -ForegroundColor Green
    }

    # ----------------------------------------------------------------
    # 7. Done
    # ----------------------------------------------------------------
    $elapsed = (Get-Date) - $startTime
    Write-Host ""
    Write-Host "  Completed in $([math]::Round($elapsed.TotalSeconds, 1)) seconds" -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  SECURITY NOTICE: Reports contain sensitive information including" -ForegroundColor Yellow
    Write-Host "  subscription IDs, tenant IDs, resource names, security contact" -ForegroundColor Yellow
    Write-Host "  emails, and compliance gaps. Handle with appropriate care." -ForegroundColor Yellow
    Write-Host "  Do NOT commit reports to version control." -ForegroundColor Yellow
    Write-Host ""

    return [PSCustomObject]@{
        PSTypeName      = 'CISBenchmarkReport'
        Score           = $score
        TotalControls   = $allResults.Count
        Passed          = $passCount
        Failed          = $failCount
        Warning         = $warningCount
        Info            = $infoCount
        Error           = $errorCount
        Results         = $allResults
        ReportPaths     = $reportPaths
        Metadata        = $metadata
        Duration        = $elapsed
        MultiSubscriptionData = $multiSubData
    }
}
