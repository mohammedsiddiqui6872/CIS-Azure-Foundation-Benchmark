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
        Scan all available subscriptions (this is now the default behavior).
        Kept for backwards compatibility.

    .PARAMETER SkipModuleCheck
        Skip Azure module validation.

    .EXAMPLE
        Invoke-CISAzureBenchmark -OutputDirectory ./reports

    .EXAMPLE
        Invoke-CISAzureBenchmark -AllSubscriptions -OutputDirectory ./reports

    .EXAMPLE
        Invoke-CISAzureBenchmark -Section '7','8' -AssessmentStatus Automated

    .PARAMETER Parallel
        When used with -AllSubscriptions (or the default multi-subscription mode),
        scans subscriptions concurrently using ForEach-Object -Parallel (PowerShell 7+ only).
        Falls back to sequential scanning with a warning on PowerShell 5.1.

    .PARAMETER ThrottleLimit
        Maximum number of subscriptions to scan concurrently when -Parallel is specified.
        Defaults to 5. Only effective when -Parallel is also specified.

    .EXAMPLE
        Invoke-CISAzureBenchmark -ProfileLevel 1 -OutputFormat HTML

    .EXAMPLE
        Invoke-CISAzureBenchmark -Parallel -ThrottleLimit 3 -OutputDirectory ./reports
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
        [ValidateSet('HTML', 'JSON', 'CSV', 'SARIF', 'All')]
        [string[]]$OutputFormat = @('All'),

        [Parameter()]
        [string]$ReportName,

        [Parameter()]
        [string]$SubscriptionId,

        [Parameter()]
        [switch]$AllSubscriptions,

        [Parameter()]
        [switch]$Parallel,

        [Parameter()]
        [ValidateRange(1, 20)]
        [int]$ThrottleLimit = 5,

        [Parameter()]
        [switch]$SkipModuleCheck,

        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [hashtable]$ExcludeResourceTag,

        [Parameter()]
        [switch]$NoAutoOpen
    )

    $ErrorActionPreference = 'Continue'
    $startTime = Get-Date

    # Suppress noisy Azure module deprecation/breaking change warnings
    $savedEnvVar = $env:SuppressAzurePowerShellBreakingChangeWarnings
    $env:SuppressAzurePowerShellBreakingChangeWarnings = 'true'
    $savedWarningPref = $WarningPreference
    $WarningPreference = 'SilentlyContinue'
    try { Update-AzConfig -DisplayBreakingChangeWarning $false -ErrorAction SilentlyContinue | Out-Null } catch { }

    # Reset progress timing for accurate ETA in this run
    $script:CISProgressTimes = [System.Collections.Generic.List[double]]::new()
    $script:CISProgressLastCheck = $null

  try {
    # Load config overrides if specified
    if ($ConfigPath) {
        Set-CISConfigOverride -ConfigPath $ConfigPath
    }

    # Banner
    Write-Host ''
    Write-Host '  +============================================================+' -ForegroundColor DarkCyan
    Write-Host '  |                                                            |' -ForegroundColor DarkCyan
    Write-Host '  |' -ForegroundColor DarkCyan -NoNewline
    Write-Host '    CIS Microsoft Azure Foundations Benchmark      ' -ForegroundColor Cyan -NoNewline
    Write-Host '|' -ForegroundColor DarkCyan
    Write-Host '  |' -ForegroundColor DarkCyan -NoNewline
    $versionStr = "$($script:CISBenchmarkVersion)  |  155 Controls"
    $versionPad = ' ' * [math]::Max(0, 45 - $versionStr.Length)
    Write-Host "             $versionStr$versionPad" -ForegroundColor White -NoNewline
    Write-Host '|' -ForegroundColor DarkCyan
    Write-Host '  |                                                            |' -ForegroundColor DarkCyan
    Write-Host '  |' -ForegroundColor DarkCyan -NoNewline
    Write-Host '              powershellnerd.com                   ' -ForegroundColor Yellow -NoNewline
    Write-Host '|' -ForegroundColor DarkCyan
    Write-Host '  |                                                            |' -ForegroundColor DarkCyan
    Write-Host '  +============================================================+' -ForegroundColor DarkCyan
    Write-Host ''

    # ----------------------------------------------------------------
    # 1. Load control definitions
    # ----------------------------------------------------------------
    $defPath = Join-Path (Join-Path (Join-Path $PSScriptRoot '..') 'Data') 'ControlDefinitions.psd1'
    if (-not (Test-Path $defPath)) {
        Write-Error "Control definitions file not found: $defPath"
        return
    }

    try {
        $definitions = Import-PowerShellDataFile -Path $defPath
    }
    catch {
        Write-Error "Failed to parse control definitions file '$defPath': $($_.Exception.Message)"
        return
    }
    $allControls = $definitions.Controls
    if (-not $allControls -or $allControls.Count -eq 0) {
        Write-Error "Control definitions file is missing or has an empty 'Controls' key."
        return
    }
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
                $ctrl.ControlId -eq $_ -or
                $ctrl.ControlId.StartsWith("$_.") -or
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

    Write-Host "  Running $($controls.Count) checks`($automatedCount automated, $manualCount manual`)" -ForegroundColor Yellow
    Write-Host ""

    if ($controls.Count -eq 0) {
        Write-Warning "No controls match the specified filters."
        return
    }

    # ----------------------------------------------------------------
    # 3. Determine subscriptions to scan
    # ----------------------------------------------------------------
    # Default: scan ALL enabled subscriptions automatically.
    # Use -SubscriptionId to target a single subscription instead.

    # Ensure Azure is connected before enumerating subscriptions
    $azContext = $null
    try { $azContext = Get-AzContext -ErrorAction Stop } catch { $azContext = $null }
    if (-not $azContext -or -not $azContext.Subscription) {
        Write-Host '  Azure is not connected. Launching interactive login...' -ForegroundColor Yellow
        try {
            Connect-AzAccount -ErrorAction Stop | Out-Null
            $azContext = Get-AzContext -ErrorAction Stop
            Write-Host '  Azure connected successfully.' -ForegroundColor Green
            Write-Host ''
        }
        catch {
            Write-Error "Failed to connect to Azure: $($_.Exception.Message)"
            return
        }
    }

    $subscriptionsToScan = @()

    if ($SubscriptionId) {
        # User explicitly chose a single subscription
        $subscriptionsToScan = @($null)
    } else {
        # Scan all enabled subscriptions by default
        $AllSubscriptions = $true
        $subscriptionsToScan = @(Get-AzSubscription -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq 'Enabled' })
        if ($subscriptionsToScan.Count -eq 0) {
            Write-Error 'No enabled subscriptions found.'
            return
        }
        Write-Host "  Scanning $($subscriptionsToScan.Count) subscription`(s`):" -ForegroundColor Cyan
        foreach ($sub in $subscriptionsToScan) {
            Write-Host "    - $($sub.Name)" -ForegroundColor White
        }
        Write-Host ''
    }

    # ----------------------------------------------------------------
    # 4. Run scans (single or multi-subscription)
    # ----------------------------------------------------------------
    $multiSubData = @{}
    $combinedResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $primaryMetadata = $null
    $subIndex = 0

    # Determine whether to use parallel scanning
    $useParallel = $false
    if ($Parallel -and $AllSubscriptions -and $subscriptionsToScan.Count -gt 1) {
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $useParallel = $true
            Write-Host "  Parallel scanning enabled (ThrottleLimit: $ThrottleLimit)" -ForegroundColor Cyan
        } else {
            Write-Warning "Parallel scanning requires PowerShell 7+. Current version: $($PSVersionTable.PSVersion). Falling back to sequential scanning."
        }
    }

    if ($useParallel) {
        # ============================================================
        # PARALLEL multi-subscription scan (PowerShell 7+ only)
        # ============================================================
        # Use a thread-safe ConcurrentDictionary for per-sub data and ConcurrentBag for combined results
        $parallelMultiSubData = [System.Collections.Concurrent.ConcurrentDictionary[string, hashtable]]::new()
        $parallelCombinedResults = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
        $parallelPrimaryMeta = [System.Collections.Concurrent.ConcurrentDictionary[string, hashtable]]::new()

        # Capture the module base path so parallel runspaces can import the module
        $moduleBasePath = $PSScriptRoot | Split-Path -Parent
        $psd1Path = Join-Path $moduleBasePath 'CISAzureBenchmark.psd1'

        # Separate tenant-level (Identity Services) from subscription-level controls.
        # Identity checks query Microsoft Graph at the tenant level and produce identical
        # results regardless of which subscription is active — run them once on the main thread.
        $identityControls = @($controls | Where-Object { $_.Section -eq 'Identity Services' })
        $subscriptionControls = @($controls | Where-Object { $_.Section -ne 'Identity Services' })

        $identityResults = @()
        if ($identityControls.Count -gt 0) {
            Write-Host "  Running $($identityControls.Count) tenant-level identity check(s) (once for all subscriptions)..." -ForegroundColor Yellow
            $firstSub = $subscriptionsToScan[0]
            Set-AzContext -SubscriptionId $firstSub.Id -ErrorAction SilentlyContinue | Out-Null
            $idEnvInfo = Initialize-CISEnvironment `
                -SubscriptionId $firstSub.Id `
                -SkipModuleCheck:$SkipModuleCheck `
                -ControlsToRun $identityControls

            $primaryMetadata = @{
                SubscriptionName = $idEnvInfo.SubscriptionName
                SubscriptionId   = $idEnvInfo.SubscriptionId
                TenantId         = $idEnvInfo.TenantId
                ScannedBy        = $idEnvInfo.ScannedBy
                ScanTimestamp    = $idEnvInfo.ScanTimestamp
            }

            $idCache = Initialize-CISResourceCache -ControlsToRun $identityControls
            foreach ($ctrl in $identityControls) {
                $result = Invoke-CISCheckSafely `
                    -ControlDef $ctrl `
                    -ResourceCache $idCache `
                    -EnvironmentInfo $idEnvInfo
                if ($result) {
                    $identityResults += $result
                    $combinedResults.Add($result)
                }
            }
            Write-Host "  Identity checks complete ($($identityResults.Count) results)" -ForegroundColor Green
            Write-Host ""
        }

        Write-Host "  Launching parallel scans for $($subscriptionsToScan.Count) subscriptions..." -ForegroundColor Yellow
        Write-Host ""

        # Pre-serialize identity results so parallel runspaces can include them
        $identityResultsForParallel = $identityResults

        $subscriptionsToScan | ForEach-Object -Parallel {
            $targetSub = $_
            $subId = $targetSub.Id
            $subName = $targetSub.Name

            # Access thread-safe collections via $using: scope
            $bag = $using:parallelCombinedResults
            $subDataDict = $using:parallelMultiSubData
            $metaDict = $using:parallelPrimaryMeta
            $controlDefs = $using:subscriptionControls
            $idResults = $using:identityResultsForParallel
            $skipMod = $using:SkipModuleCheck
            $excludeTag = $using:ExcludeResourceTag
            $modPath = $using:psd1Path

            # Import the module in this runspace so all private functions are available
            Import-Module $modPath -Force -ErrorAction Stop

            # Suppress Azure deprecation warnings in this runspace
            $env:SuppressAzurePowerShellBreakingChangeWarnings = 'true'
            $WarningPreference = 'SilentlyContinue'
            try { Update-AzConfig -DisplayBreakingChangeWarning $false -ErrorAction SilentlyContinue | Out-Null } catch { }

            # Each parallel runspace must set its own Az context
            Set-AzContext -SubscriptionId $subId -ErrorAction Stop | Out-Null

            # Initialize environment for this subscription
            $envInfo = Initialize-CISEnvironment `
                -SubscriptionId $subId `
                -SkipModuleCheck:$skipMod `
                -ControlsToRun $controlDefs

            if (-not $envInfo.IsValid) {
                Write-Warning "[$subName] Skipping - initialization failed"
                foreach ($err in $envInfo.Errors) { Write-Warning "  [$subName] $err" }
                return  # continue in parallel context
            }

            # Store primary metadata from the first subscription to complete
            [void]$metaDict.TryAdd('first', @{
                SubscriptionName = $envInfo.SubscriptionName
                SubscriptionId   = $envInfo.SubscriptionId
                TenantId         = $envInfo.TenantId
                ScannedBy        = $envInfo.ScannedBy
                ScanTimestamp    = $envInfo.ScanTimestamp
            })

            Write-Host "  [$subName] Pre-fetching Azure resources..." -ForegroundColor Yellow
            $cacheParams = @{ ControlsToRun = $controlDefs }
            if ($excludeTag) { $cacheParams.ExcludeResourceTag = $excludeTag }
            $resourceCache = Initialize-CISResourceCache @cacheParams
            Write-Host "  [$subName] Resource cache ready" -ForegroundColor Green

            # Execute subscription-level checks only (identity checks already ran on main thread)
            Write-Host "  [$subName] Running compliance checks..." -ForegroundColor Yellow
            $subResults = [System.Collections.Generic.List[PSCustomObject]]::new()

            # Include the shared identity results in this subscription's results
            foreach ($idResult in $idResults) {
                $subResults.Add($idResult)
            }

            foreach ($ctrl in $controlDefs) {
                $result = Invoke-CISCheckSafely `
                    -ControlDef $ctrl `
                    -ResourceCache $resourceCache `
                    -EnvironmentInfo $envInfo

                if ($result) {
                    $subResults.Add($result)
                    $bag.Add($result)
                }
            }

            # Post-process: convert false PASSes from failed cache fetches to WARNING
            if ($resourceCache.FailedResourceTypes -and $resourceCache.FailedResourceTypes.Count -gt 0) {
                $resourceDependencyMap = @{
                    'Network Security Groups' = @('NSGPortCheck')
                    'Storage Accounts'        = @('StorageAccountProperty', 'StorageBlobProperty', 'StorageFileProperty')
                    'Key Vaults'              = @('KeyVaultProperty', 'KeyVaultKeyExpiry', 'KeyVaultSecretExpiry')
                    'Activity Log Alerts'     = @('ActivityLogAlert')
                    'Application Gateways'    = @('_section:Networking Services')
                    'Virtual Networks'        = @('_section:Networking Services')
                    'Network Watchers'        = @('_section:Networking Services')
                    'Databricks Workspaces'   = @('_section:Analytics Services')
                }
                $affectedPatterns  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                $affectedSections  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($failedType in $resourceCache.FailedResourceTypes) {
                    if ($resourceDependencyMap.ContainsKey($failedType)) {
                        foreach ($dep in $resourceDependencyMap[$failedType]) {
                            if ($dep.StartsWith('_section:')) {
                                [void]$affectedSections.Add($dep.Substring(9))
                            } else {
                                [void]$affectedPatterns.Add($dep)
                            }
                        }
                    }
                }
                foreach ($r in $subResults) {
                    if ($r.Status -eq 'PASS' -and $r.TotalResources -eq 0) {
                        $c = $controlDefs | Where-Object { $_.ControlId -eq $r.ControlId } | Select-Object -First 1
                        if ($c -and (($c.CheckPattern -and $affectedPatterns.Contains($c.CheckPattern)) -or
                                        ($c.Section -and $affectedSections.Contains($c.Section)))) {
                            $r.Status = 'WARNING'
                            $r.Details = "Resource fetch failed for this check's dependencies. Result may be inaccurate. Original: $($r.Details)"
                        }
                    }
                }
            }

            # Store per-subscription data (includes identity results for per-sub reports)
            [void]$subDataDict.TryAdd($envInfo.SubscriptionId, @{
                Name     = $envInfo.SubscriptionName
                TenantId = $envInfo.TenantId
                Results  = $subResults.ToArray()
            })

            # Per-subscription summary
            $subPass = ($subResults | Where-Object Status -eq 'PASS').Count
            $subFail = ($subResults | Where-Object Status -eq 'FAIL').Count
            $subInfo = ($subResults | Where-Object Status -eq 'INFO').Count
            $subWarn = ($subResults | Where-Object Status -eq 'WARNING').Count
            $subError = ($subResults | Where-Object Status -eq 'ERROR').Count
            $subDenom = $subResults.Count - $subInfo - $subWarn
            $subScore = if ($subDenom -gt 0) { [math]::Round(($subPass / $subDenom) * 100, 1) } else { 0 }
            $scoreColor = if ($subScore -ge 80) { 'Green' } elseif ($subScore -ge 50) { 'Yellow' } else { 'Red' }
            Write-Host ""
            Write-Host "  [$subName] Score: $subScore% | Pass: $subPass | Fail: $subFail | Error: $subError" -ForegroundColor $scoreColor
            Write-Host ""

        } -ThrottleLimit $ThrottleLimit

        # Transfer parallel results back to the main-thread collections
        foreach ($kvp in $parallelMultiSubData.GetEnumerator()) {
            $multiSubData[$kvp.Key] = $kvp.Value
        }
        foreach ($r in $parallelCombinedResults) {
            $combinedResults.Add($r)
        }
        if (-not $primaryMetadata -and $parallelPrimaryMeta.ContainsKey('first')) {
            $primaryMetadata = $parallelPrimaryMeta['first']
        }

    } else {
        # ============================================================
        # SEQUENTIAL scan (default, or PS 5.1 fallback)
        # ============================================================
        # Track tenant-level (Identity Services) results from the first subscription
        # to avoid duplicate checks in multi-sub mode (they query Graph, not per-sub resources)
        $tenantLevelResults = $null

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
                    ScannedBy        = $envInfo.ScannedBy
                    ScanTimestamp    = $envInfo.ScanTimestamp
                }
            }

            Write-Host "  Subscription: $($envInfo.SubscriptionName) ($($envInfo.SubscriptionId))" -ForegroundColor Cyan
            Write-Host "  Tenant:       $($envInfo.TenantId)" -ForegroundColor Cyan
            Write-Host ""

            # Pre-fetch resources
            Write-Host "  Pre-fetching Azure resources..." -ForegroundColor Yellow
            $cacheParams = @{ ControlsToRun = $controls }
            if ($ExcludeResourceTag) { $cacheParams.ExcludeResourceTag = $ExcludeResourceTag }
            $resourceCache = Initialize-CISResourceCache @cacheParams
            if ($resourceCache.FetchWarnings -and $resourceCache.FetchWarnings.Count -gt 0) {
                # Temporarily restore warning preference to show critical cache warnings
                $WarningPreference = $savedWarningPref
                foreach ($fw in $resourceCache.FetchWarnings) { Write-Warning $fw }
                $WarningPreference = 'SilentlyContinue'
            }
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

                # Skip tenant-level (Identity Services) checks on subsequent subscriptions —
                # they query Microsoft Graph at the tenant level and produce identical results
                if ($AllSubscriptions -and $subIndex -gt 1 -and $ctrl.Section -eq 'Identity Services' -and $null -ne $tenantLevelResults) {
                    $cachedResult = $tenantLevelResults[$ctrl.ControlId]
                    if ($cachedResult) {
                        $subResults.Add($cachedResult)
                        $combinedResults.Add($cachedResult)
                        continue
                    }
                }

                $result = Invoke-CISCheckSafely `
                    -ControlDef $ctrl `
                    -ResourceCache $resourceCache `
                    -EnvironmentInfo $envInfo

                if ($result) {
                    $subResults.Add($result)
                    $combinedResults.Add($result)
                }
            }

            # Cache tenant-level results from first subscription for reuse
            if ($AllSubscriptions -and $subIndex -eq 1 -and $null -eq $tenantLevelResults) {
                $tenantLevelResults = @{}
                foreach ($r in $subResults) {
                    $ctrlDef = $controls | Where-Object { $_.ControlId -eq $r.ControlId } | Select-Object -First 1
                    if ($ctrlDef -and $ctrlDef.Section -eq 'Identity Services') {
                        $tenantLevelResults[$r.ControlId] = $r
                    }
                }
                if ($tenantLevelResults.Count -gt 0) {
                    Write-Verbose "  Cached $($tenantLevelResults.Count) tenant-level identity results for reuse across subscriptions"
                }
            }

            Write-Progress -Activity "CIS Azure Benchmark $($script:CISBenchmarkVersion)" -Completed

            # Post-process: convert false PASSes from failed cache fetches to WARNING
            if ($resourceCache.FailedResourceTypes -and $resourceCache.FailedResourceTypes.Count -gt 0) {
                # Map resource types to check patterns/sections that depend on them
                $resourceDependencyMap = @{
                    'Network Security Groups' = @('NSGPortCheck')
                    'Storage Accounts'        = @('StorageAccountProperty', 'StorageBlobProperty', 'StorageFileProperty')
                    'Key Vaults'              = @('KeyVaultProperty', 'KeyVaultKeyExpiry', 'KeyVaultSecretExpiry')
                    'Activity Log Alerts'     = @('ActivityLogAlert')
                    'Application Gateways'    = @('_section:Networking Services')
                    'Virtual Networks'        = @('_section:Networking Services')
                    'Network Watchers'        = @('_section:Networking Services')
                    'Databricks Workspaces'   = @('_section:Analytics Services')
                }
                $affectedPatterns  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                $affectedSections  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($failedType in $resourceCache.FailedResourceTypes) {
                    if ($resourceDependencyMap.ContainsKey($failedType)) {
                        foreach ($dep in $resourceDependencyMap[$failedType]) {
                            if ($dep.StartsWith('_section:')) {
                                [void]$affectedSections.Add($dep.Substring(9))
                            } else {
                                [void]$affectedPatterns.Add($dep)
                            }
                        }
                    }
                }
                foreach ($r in $subResults) {
                    if ($r.Status -eq 'PASS' -and $r.TotalResources -eq 0) {
                        $ctrl = $controls | Where-Object { $_.ControlId -eq $r.ControlId } | Select-Object -First 1
                        if ($ctrl -and (($ctrl.CheckPattern -and $affectedPatterns.Contains($ctrl.CheckPattern)) -or
                                        ($ctrl.Section -and $affectedSections.Contains($ctrl.Section)))) {
                            $r.Status = 'WARNING'
                            $r.Details = "Resource fetch failed for this check's dependencies. Result may be inaccurate. Original: $($r.Details)"
                        }
                    }
                }
            }

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
    }

    # Use combined results for everything from here
    $allResults = $combinedResults

    # ----------------------------------------------------------------
    # 5. Summary
    # ----------------------------------------------------------------
    # Single-pass counting for efficiency
    $passCount = 0; $failCount = 0; $warningCount = 0; $infoCount = 0; $errorCount = 0
    foreach ($r in $allResults) {
        switch ($r.Status) {
            'PASS'    { $passCount++ }
            'FAIL'    { $failCount++ }
            'WARNING' { $warningCount++ }
            'INFO'    { $infoCount++ }
            'ERROR'   { $errorCount++ }
        }
    }

    # Score excludes INFO (manual checks), WARNING (indeterminate), and ERROR (broken checks) from denominator
    $scoreDenom = $allResults.Count - $infoCount - $warningCount - $errorCount
    $score = if ($scoreDenom -gt 0) { [math]::Round(($passCount / $scoreDenom) * 100, 1) } else { -1 }

    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "  RESULTS SUMMARY$(if ($AllSubscriptions) { " (All $($multiSubData.Count) Subscriptions Combined)" })" -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
    $scoreDisplay = if ($score -lt 0) { 'N/A (no evaluated controls)' } else { "$score%" }
    $scoreColor = if ($score -lt 0) { 'DarkGray' } elseif ($score -ge 80) { 'Green' } elseif ($score -ge 50) { 'Yellow' } else { 'Red' }
    Write-Host "  Automated Checks Score: $scoreDisplay" -ForegroundColor $scoreColor
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
    # Validate output path
    $resolvedOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
    if ($resolvedOutput -match '^\\\\') {
        Write-Warning "Output directory is a UNC path ($resolvedOutput). Reports contain sensitive data - ensure the share is secured."
    }
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    $metadata = if ($primaryMetadata) { $primaryMetadata } else { @{
        SubscriptionName = 'Unknown'
        SubscriptionId   = 'Unknown'
        TenantId         = 'Unknown'
        ScannedBy        = ''
        ScanTimestamp    = [DateTime]::UtcNow.ToString('o')
    } }

    if ($AllSubscriptions) {
        $metadata.SubscriptionName = "All Subscriptions ($($multiSubData.Count))"
    }

    if (-not $ReportName) {
        $subName = if ($metadata.SubscriptionName) { $metadata.SubscriptionName } else { 'Unknown' }
        $safeSub = if ($AllSubscriptions) { "AllSubscriptions" } else { $subName -replace '[^\w\-]', '_' }
        $dateStamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $ReportName = "CIS-Azure-$($script:CISBenchmarkVersion)_${safeSub}_${dateStamp}"
    }

    $formats = if ('All' -in $OutputFormat) { @('HTML', 'JSON', 'CSV', 'SARIF') } else { $OutputFormat }

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

    if ('SARIF' -in $formats) {
        $sarifPath = Join-Path $OutputDirectory "$ReportName.sarif"
        Write-Host "  Generating SARIF report..." -ForegroundColor Yellow
        $reportPaths.SARIF = New-CISSarifReport -Results $allResults -OutputPath $sarifPath -Metadata $metadata
        Write-Host "  SARIF: $sarifPath" -ForegroundColor Green
    }

    # ----------------------------------------------------------------
    # 7. Done
    # ----------------------------------------------------------------
    # Restore warning preference
    $WarningPreference = $savedWarningPref

    $elapsed = (Get-Date) - $startTime
    $elapsedDisplay = if ($elapsed.TotalMinutes -ge 1) {
        "{0}m {1}s" -f [math]::Floor($elapsed.TotalMinutes), $elapsed.Seconds
    } else {
        "$([math]::Round($elapsed.TotalSeconds, 1))s"
    }

    $scoreColor = if ($score -ge 80) { 'Green' } elseif ($score -ge 50) { 'Yellow' } else { 'Red' }
    $scoreDisplay = if ($score -eq -1) { "N/A" } else { "$score%" }

    Write-Host ''
    Write-Host '  +============================================================+' -ForegroundColor DarkCyan
    Write-Host '  |                       SCAN COMPLETE                        |' -ForegroundColor DarkCyan
    Write-Host '  +============================================================+' -ForegroundColor DarkCyan
    $boxWidth = 60  # inner width between | and |
    Write-Host '  |' -ForegroundColor DarkCyan -NoNewline
    $scoreContent = "  Score: $scoreDisplay"
    Write-Host $scoreContent -ForegroundColor $scoreColor -NoNewline
    Write-Host (' ' * [math]::Max(0, $boxWidth - $scoreContent.Length)) -NoNewline
    Write-Host '|' -ForegroundColor DarkCyan
    Write-Host '  |' -ForegroundColor DarkCyan -NoNewline
    Write-Host "  PASS: $passCount  " -ForegroundColor Green -NoNewline
    Write-Host "FAIL: $failCount  " -ForegroundColor Red -NoNewline
    Write-Host "WARN: $warningCount  " -ForegroundColor Yellow -NoNewline
    Write-Host "INFO: $infoCount  " -ForegroundColor Gray -NoNewline
    Write-Host "ERR: $errorCount" -ForegroundColor Magenta -NoNewline
    $statLine = "  PASS: $passCount  FAIL: $failCount  WARN: $warningCount  INFO: $infoCount  ERR: $errorCount"
    Write-Host (' ' * [math]::Max(0, $boxWidth - $statLine.Length)) -NoNewline
    Write-Host '|' -ForegroundColor DarkCyan
    Write-Host '  |' -ForegroundColor DarkCyan -NoNewline
    $durContent = "  Duration: $elapsedDisplay"
    Write-Host $durContent -ForegroundColor White -NoNewline
    Write-Host (' ' * [math]::Max(0, $boxWidth - $durContent.Length)) -NoNewline
    Write-Host '|' -ForegroundColor DarkCyan
    Write-Host '  +------------------------------------------------------------+' -ForegroundColor DarkCyan
    Write-Host '  |  Report Files:                                             |' -ForegroundColor DarkCyan
    foreach ($fmt in $reportPaths.Keys) {
        $fullPath = (Resolve-Path $reportPaths[$fmt]).Path
        $line = "  $($fmt.PadRight(6)) $fullPath"
        if ($line.Length -gt $boxWidth) { $line = $line.Substring(0, $boxWidth - 3) + '...' }
        $linePad = [math]::Max(0, $boxWidth - $line.Length)
        Write-Host '  |' -ForegroundColor DarkCyan -NoNewline
        Write-Host "$line" -ForegroundColor White -NoNewline
        Write-Host (' ' * $linePad) -NoNewline
        Write-Host '|' -ForegroundColor DarkCyan
    }
    Write-Host '  +============================================================+' -ForegroundColor DarkCyan
    Write-Host ''
    Write-Host '  Note: Reports contain sensitive data. Do not commit to source control.' -ForegroundColor DarkYellow
    Write-Host ''

    # Auto-open HTML report
    if (-not $NoAutoOpen -and $reportPaths.ContainsKey('HTML') -and (Test-Path $reportPaths.HTML)) {
        try {
            Start-Process (Resolve-Path $reportPaths.HTML).Path
        }
        catch {
            Write-Verbose "Could not auto-open HTML report: $($_.Exception.Message)"
        }
    }

    $resultObj = [PSCustomObject]@{
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

    # Set default display properties so the console shows a clean summary (not the full Results array)
    $defaultProps = @('Score', 'TotalControls', 'Passed', 'Failed', 'Warning', 'Info', 'Error', 'Duration')
    $defaultSet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', [string[]]$defaultProps)
    $resultObj | Add-Member MemberSet PSStandardMembers ([System.Management.Automation.PSMemberInfo[]]@($defaultSet))

    return $resultObj

  } # end try
  finally {
    # Always restore warning preference and env vars, even on Ctrl+C or early return
    $WarningPreference = $savedWarningPref
    if ($null -eq $savedEnvVar) {
        Remove-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings -ErrorAction SilentlyContinue
    } else {
        $env:SuppressAzurePowerShellBreakingChangeWarnings = $savedEnvVar
    }
  }
}
