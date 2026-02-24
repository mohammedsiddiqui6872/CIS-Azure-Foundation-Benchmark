# =============================================================================
# Section 7: Networking Services - Custom Check Functions
# CIS Microsoft Azure Foundations Benchmark v5.0.0
# =============================================================================
# Custom functions for NSG flow logs, Network Watcher, Application Gateway,
# WAF, and subnet checks. Dispatched via 'Custom' CheckPattern.
# Each function receives -ControlDef (hashtable) and -ResourceCache (hashtable).
# =============================================================================

function Test-FlowLogRetention {
    <#
    .SYNOPSIS
        Shared helper for NSG and VNet flow log retention checks.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache,

        [Parameter(Mandatory)]
        [string]$FlowLogType,

        [Parameter()]
        [string]$TargetResourceFilter = ''
    )

    try {
        $networkWatchers = @($ResourceCache.NetworkWatchers)
        if ($networkWatchers.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'WARNING' `
                -Details "No Network Watchers found. Cannot evaluate $FlowLogType flow log retention." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $totalCount    = 0
        $failedList    = [System.Collections.Generic.List[string]]::new()
        $passedCount   = 0
        $errorWatchers = [System.Collections.Generic.List[string]]::new()

        foreach ($nw in $networkWatchers) {
            try {
                $flowLogs = @(Get-AzNetworkWatcherFlowLog -NetworkWatcherName $nw.Name -ResourceGroupName $nw.ResourceGroupName -ErrorAction Stop)

                # Filter by target resource type if specified
                if ($TargetResourceFilter) {
                    $flowLogs = @($flowLogs | Where-Object {
                        $_.TargetResourceId -match $TargetResourceFilter
                    })
                }

                foreach ($flowLog in $flowLogs) {
                    $totalCount++
                    $retentionEnabled = $flowLog.RetentionPolicy.Enabled
                    $retentionDays    = $flowLog.RetentionPolicy.Days

                    # Retention of 0 with enabled = true means indefinite (pass)
                    $minRetention = if ($script:CISConfig.RetentionThresholdDays) { $script:CISConfig.RetentionThresholdDays } else { 90 }
                    if ($retentionEnabled -and ($retentionDays -ge $minRetention -or $retentionDays -eq 0)) {
                        $passedCount++
                    }
                    else {
                        $currentRetention = if ($retentionEnabled) { "$retentionDays days" } else { 'disabled' }
                        $targetId = if ($flowLog.TargetResourceId) {
                            ($flowLog.TargetResourceId -split '/')[-1]
                        } else { $flowLog.Name }
                        $failedList.Add("$targetId (retention: $currentRetention)")
                    }
                }
            }
            catch {
                $errorWatchers.Add("$($nw.Name): $(Format-CISErrorMessage $_.Exception.Message)")
            }
        }

        # If ALL watchers failed to respond, return WARNING instead of false FAIL
        if ($totalCount -eq 0 -and $errorWatchers.Count -gt 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'WARNING' `
                -Details "Could not retrieve $FlowLogType flow logs from $($errorWatchers.Count) Network Watcher(s). Errors: $($errorWatchers -join '; ')" `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        if ($totalCount -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details "No $FlowLogType flow logs found across $($networkWatchers.Count) Network Watcher(s). Flow logs should be configured." `
                -AffectedResources @("No $FlowLogType flow logs configured") `
                -TotalResources 0 -PassedResources 0 -FailedResources 1
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $retentionDaysDisplay = if ($script:CISConfig.RetentionThresholdDays) { $script:CISConfig.RetentionThresholdDays } else { 90 }
            $details = "Found $failedCount of $totalCount $FlowLogType flow log(s) with retention < $retentionDaysDisplay days: $($failedList -join '; ')"
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
            -Details "All $totalCount $FlowLogType flow log(s) have retention >= $retentionDaysDisplay days." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking $FlowLogType flow log retention: $($_.Exception.Message)"
    }
}

function Test-CIS75-NSGFlowLogRetention {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable]$ControlDef,
        [Parameter(Mandatory)] [hashtable]$ResourceCache
    )
    Test-FlowLogRetention -ControlDef $ControlDef -ResourceCache $ResourceCache -FlowLogType 'NSG'
}

function Test-CIS76-NetworkWatcher {
    <#
    .SYNOPSIS
        CIS 7.6 - Ensure Network Watcher is 'Enabled' for Azure Regions in use.
    .DESCRIPTION
        Identifies all regions where resources are deployed and checks that a
        Network Watcher instance exists in each region.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $networkWatchers = @($ResourceCache.NetworkWatchers)

        # Determine regions in use from VNets, NSGs, and other cached resources
        $usedRegions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        $vnets = @($ResourceCache.VirtualNetworks)
        foreach ($vnet in $vnets) {
            if ($vnet.Location) { [void]$usedRegions.Add($vnet.Location) }
        }

        $nsgs = @($ResourceCache.NSGs)
        foreach ($nsg in $nsgs) {
            if ($nsg.Location) { [void]$usedRegions.Add($nsg.Location) }
        }

        $appGws = @($ResourceCache.ApplicationGateways)
        foreach ($appGw in $appGws) {
            if ($appGw.Location) { [void]$usedRegions.Add($appGw.Location) }
        }

        if ($usedRegions.Count -eq 0) {
            # Fallback: use locations from additional cached resources or Get-AzLocation
            $storageAccounts = @($ResourceCache.StorageAccounts)
            foreach ($sa in $storageAccounts) {
                if ($sa.Location) { [void]$usedRegions.Add($sa.Location) }
            }
            $keyVaults = @($ResourceCache.KeyVaults)
            foreach ($kv in $keyVaults) {
                if ($kv.Location) { [void]$usedRegions.Add($kv.Location) }
            }
            # Final fallback: Azure locations with resources
            if ($usedRegions.Count -eq 0) {
                try {
                    $locations = @(Get-AzLocation -ErrorAction Stop | Where-Object { $_.RegionType -eq 'Physical' })
                    foreach ($loc in $locations) {
                        if ($loc.Location) { [void]$usedRegions.Add($loc.Location) }
                    }
                }
                catch {
                    Write-Verbose "Failed to enumerate Azure locations: $($_.Exception.Message)"
                }
            }
        }

        if ($usedRegions.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'WARNING' `
                -Details "Could not determine regions in use. Unable to validate Network Watcher coverage." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $watcherRegions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($nw in $networkWatchers) {
            if ($nw.Location) { [void]$watcherRegions.Add($nw.Location) }
        }

        $totalCount  = $usedRegions.Count
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        foreach ($region in $usedRegions) {
            if ($watcherRegions.Contains($region)) {
                $passedCount++
            }
            else {
                $failedList.Add($region)
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Network Watcher is missing in $failedCount of $totalCount region(s): $($failedList -join ', ')"
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
            -Details "Network Watcher is enabled in all $totalCount region(s) in use: $($usedRegions -join ', ')." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking Network Watcher coverage: $($_.Exception.Message)"
    }
}

function Test-CIS78-VNetFlowLogRetention {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable]$ControlDef,
        [Parameter(Mandatory)] [hashtable]$ResourceCache
    )
    Test-FlowLogRetention -ControlDef $ControlDef -ResourceCache $ResourceCache -FlowLogType 'VNet' -TargetResourceFilter 'Microsoft\.Network/virtualNetworks'
}

function Test-CIS710-AppGatewayWAF {
    <#
    .SYNOPSIS
        CIS 7.10 - Ensure Azure WAF is enabled on Application Gateway.
    .DESCRIPTION
        Checks that Application Gateways have WAF enabled via WAF_v2 SKU with
        WebApplicationFirewallConfiguration or an associated WAF policy.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $appGateways = @($ResourceCache.ApplicationGateways)
        if ($appGateways.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No Application Gateways found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $totalCount  = $appGateways.Count
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        foreach ($gw in $appGateways) {
            $hasWAF = $false

            # Check SKU for WAF tier
            if ($gw.Sku -and $gw.Sku.Tier -match 'WAF') {
                $hasWAF = $true
            }

            # Check for WebApplicationFirewallConfiguration
            if (-not $hasWAF -and $gw.WebApplicationFirewallConfiguration -and $gw.WebApplicationFirewallConfiguration.Enabled) {
                $hasWAF = $true
            }

            # Check for FirewallPolicy (WAF policy attached)
            if (-not $hasWAF -and $gw.FirewallPolicy -and $gw.FirewallPolicy.Id) {
                $hasWAF = $true
            }

            if ($hasWAF) {
                $passedCount++
            }
            else {
                $skuTier = if ($gw.Sku) { $gw.Sku.Tier } else { 'Unknown' }
                $failedList.Add("$($gw.Name) (SKU: $skuTier)")
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount of $totalCount Application Gateway(s) without WAF enabled: $($failedList -join '; ')"
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
            -Details "All $totalCount Application Gateway(s) have WAF enabled." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking Application Gateway WAF: $($_.Exception.Message)"
    }
}

function Test-CIS711-SubnetNSG {
    <#
    .SYNOPSIS
        CIS 7.11 - Ensure subnets are associated with network security groups.
    .DESCRIPTION
        Checks all subnets across all VNets, excluding special subnets like
        GatewaySubnet, AzureBastionSubnet, AzureFirewallSubnet, and
        AzureFirewallManagementSubnet.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $vnets = @($ResourceCache.VirtualNetworks)
        if ($vnets.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No Virtual Networks found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        # Subnets that do not require or support NSGs
        $exemptSubnets = @(
            'GatewaySubnet',
            'AzureBastionSubnet',
            'AzureFirewallSubnet',
            'AzureFirewallManagementSubnet',
            'RouteServerSubnet'
        )

        $totalCount  = 0
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        foreach ($vnet in $vnets) {
            foreach ($subnet in $vnet.Subnets) {
                if ($subnet.Name -in $exemptSubnets) { continue }

                $totalCount++
                if ($subnet.NetworkSecurityGroup -and $subnet.NetworkSecurityGroup.Id) {
                    $passedCount++
                }
                else {
                    $failedList.Add("$($vnet.Name)/$($subnet.Name)")
                }
            }
        }

        if ($totalCount -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No evaluable subnets found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount of $totalCount subnet(s) without NSGs: $($failedList -join '; ')"
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
            -Details "All $totalCount evaluable subnet(s) have NSGs associated." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking subnet NSG associations: $($_.Exception.Message)"
    }
}

function Test-CIS712-AppGatewayTLS {
    <#
    .SYNOPSIS
        CIS 7.12 - Ensure SSL policy MinProtocolVersion is TLSv1_2 or higher.
    .DESCRIPTION
        Checks each Application Gateway's SSL policy for minimum protocol version
        of TLSv1_2 or TLSv1_3.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $appGateways = @($ResourceCache.ApplicationGateways)
        if ($appGateways.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No Application Gateways found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $acceptableVersions = @('TLSv1_2', 'TLSv1_3')
        $totalCount  = $appGateways.Count
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        foreach ($gw in $appGateways) {
            $minVersion = $null

            if ($gw.SslPolicy) {
                $minVersion = $gw.SslPolicy.MinProtocolVersion
                # Also check predefined policy names that enforce TLS 1.2+
                if (-not $minVersion -and $gw.SslPolicy.PolicyName) {
                    $policyName = $gw.SslPolicy.PolicyName
                    # Predefined policies with TLS 1.2 minimum
                    $tls12Policies = @(
                        'AppGwSslPolicy20170401S',
                        'AppGwSslPolicy20220101',
                        'AppGwSslPolicy20220101S'
                    )
                    if ($policyName -in $tls12Policies) {
                        $minVersion = 'TLSv1_2'
                    }
                }
            }

            if ($minVersion -and $minVersion -in $acceptableVersions) {
                $passedCount++
            }
            else {
                $currentVersion = if ($minVersion) { $minVersion } else { 'Not set (defaults may allow TLS 1.0/1.1)' }
                $failedList.Add("$($gw.Name) (MinProtocolVersion: $currentVersion)")
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount of $totalCount Application Gateway(s) without TLS 1.2+ minimum: $($failedList -join '; ')"
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
            -Details "All $totalCount Application Gateway(s) enforce TLS 1.2 or higher." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking Application Gateway TLS policy: $($_.Exception.Message)"
    }
}

function Test-CIS713-AppGatewayHTTP2 {
    <#
    .SYNOPSIS
        CIS 7.13 - Ensure 'HTTP2' is set to 'Enabled' on Azure Application Gateway.
    .DESCRIPTION
        Checks that EnableHttp2 is true on each Application Gateway.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $appGateways = @($ResourceCache.ApplicationGateways)
        if ($appGateways.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No Application Gateways found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $totalCount  = $appGateways.Count
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        foreach ($gw in $appGateways) {
            if ($gw.EnableHttp2 -eq $true) {
                $passedCount++
            }
            else {
                $failedList.Add("$($gw.Name) (EnableHttp2: $($gw.EnableHttp2))")
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount of $totalCount Application Gateway(s) without HTTP/2 enabled: $($failedList -join '; ')"
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
            -Details "All $totalCount Application Gateway(s) have HTTP/2 enabled." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking Application Gateway HTTP/2: $($_.Exception.Message)"
    }
}

function Test-CIS714-WAFRequestBodyInspection {
    <#
    .SYNOPSIS
        CIS 7.14 - Ensure request body inspection is enabled in WAF policy.
    .DESCRIPTION
        Checks WAF policies associated with Application Gateways to verify
        request body inspection is enabled.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $appGateways = @($ResourceCache.ApplicationGateways)
        if ($appGateways.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No Application Gateways found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        # Collect unique WAF policy IDs from Application Gateways
        $wafPolicyIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($gw in $appGateways) {
            if ($gw.FirewallPolicy -and $gw.FirewallPolicy.Id) {
                [void]$wafPolicyIds.Add($gw.FirewallPolicy.Id)
            }
        }

        if ($wafPolicyIds.Count -eq 0) {
            # Check inline WAF configuration
            $gwsWithWAF = @($appGateways | Where-Object { $_.WebApplicationFirewallConfiguration })
            if ($gwsWithWAF.Count -eq 0) {
                return New-CISCheckResult `
                    -ControlId $ControlDef.ControlId `
                    -Title $ControlDef.Title `
                    -Status 'WARNING' `
                    -Details "No WAF policies or configurations found on $($appGateways.Count) Application Gateway(s)." `
                    -TotalResources $appGateways.Count -PassedResources 0 -FailedResources 0
            }

            $totalCount  = $gwsWithWAF.Count
            $failedList  = [System.Collections.Generic.List[string]]::new()
            $passedCount = 0

            foreach ($gw in $gwsWithWAF) {
                if ($gw.WebApplicationFirewallConfiguration.RequestBodyCheck -eq $true) {
                    $passedCount++
                }
                else {
                    $failedList.Add("$($gw.Name) (inline WAF: RequestBodyCheck disabled)")
                }
            }

            $failedCount = $failedList.Count
            if ($failedCount -gt 0) {
                return New-CISCheckResult `
                    -ControlId $ControlDef.ControlId `
                    -Title $ControlDef.Title `
                    -Status 'FAIL' `
                    -Details "$failedCount of $totalCount WAF configuration(s) have request body inspection disabled: $($failedList -join '; ')" `
                    -AffectedResources $failedList.ToArray() `
                    -TotalResources $totalCount -PassedResources $passedCount -FailedResources $failedCount
            }

            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "All $totalCount WAF configuration(s) have request body inspection enabled." `
                -TotalResources $totalCount -PassedResources $passedCount -FailedResources 0
        }

        # Check WAF policies
        $totalCount  = $wafPolicyIds.Count
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        foreach ($policyId in $wafPolicyIds) {
            try {
                $policy = Get-AzResource -ResourceId $policyId -ExpandProperties -ErrorAction Stop
                $policyName = ($policyId -split '/')[-1]

                $requestBodyCheck = $false
                if ($policy.Properties.PolicySettings -and $policy.Properties.PolicySettings.RequestBodyCheck -eq $true) {
                    $requestBodyCheck = $true
                }
                # Alternative property path
                if (-not $requestBodyCheck -and $policy.Properties.policySettings -and $policy.Properties.policySettings.requestBodyCheck -eq $true) {
                    $requestBodyCheck = $true
                }

                if ($requestBodyCheck) {
                    $passedCount++
                }
                else {
                    $failedList.Add($policyName)
                }
            }
            catch {
                $policyName = ($policyId -split '/')[-1]
                $failedList.Add("$policyName [Error: $($_.Exception.Message)]")
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "$failedCount of $totalCount WAF policy(ies) have request body inspection disabled: $($failedList -join '; ')"
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
            -Details "All $totalCount WAF policy(ies) have request body inspection enabled." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking WAF request body inspection: $($_.Exception.Message)"
    }
}

function Test-CIS715-WAFBotProtection {
    <#
    .SYNOPSIS
        CIS 7.15 - Ensure bot protection is enabled in WAF policy.
    .DESCRIPTION
        Checks WAF policies for the presence of bot protection managed rule sets.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $appGateways = @($ResourceCache.ApplicationGateways)
        if ($appGateways.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No Application Gateways found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        # Collect unique WAF policy IDs
        $wafPolicyIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($gw in $appGateways) {
            if ($gw.FirewallPolicy -and $gw.FirewallPolicy.Id) {
                [void]$wafPolicyIds.Add($gw.FirewallPolicy.Id)
            }
        }

        if ($wafPolicyIds.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'WARNING' `
                -Details "No WAF policies found on $($appGateways.Count) Application Gateway(s). Bot protection requires WAF policy." `
                -TotalResources $appGateways.Count -PassedResources 0 -FailedResources 0
        }

        $totalCount  = $wafPolicyIds.Count
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        foreach ($policyId in $wafPolicyIds) {
            try {
                $policy = Get-AzResource -ResourceId $policyId -ExpandProperties -ErrorAction Stop
                $policyName = ($policyId -split '/')[-1]

                $hasBotProtection = $false

                # Check ManagedRules for bot protection rule set
                $managedRules = $policy.Properties.ManagedRules
                if (-not $managedRules) { $managedRules = $policy.Properties.managedRules }

                if ($managedRules -and $managedRules.ManagedRuleSets) {
                    foreach ($ruleSet in $managedRules.ManagedRuleSets) {
                        if ($ruleSet.RuleSetType -match 'BotProtection|Microsoft_BotManagerRuleSet') {
                            $hasBotProtection = $true
                            break
                        }
                    }
                }
                if (-not $hasBotProtection -and $managedRules -and $managedRules.managedRuleSets) {
                    foreach ($ruleSet in $managedRules.managedRuleSets) {
                        $ruleSetType = if ($ruleSet.ruleSetType) { $ruleSet.ruleSetType } else { $ruleSet.RuleSetType }
                        if ($ruleSetType -match 'BotProtection|Microsoft_BotManagerRuleSet') {
                            $hasBotProtection = $true
                            break
                        }
                    }
                }

                if ($hasBotProtection) {
                    $passedCount++
                }
                else {
                    $failedList.Add($policyName)
                }
            }
            catch {
                $policyName = ($policyId -split '/')[-1]
                $failedList.Add("$policyName [Error: $($_.Exception.Message)]")
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "$failedCount of $totalCount WAF policy(ies) do not have bot protection enabled: $($failedList -join '; ')"
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
            -Details "All $totalCount WAF policy(ies) have bot protection enabled." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking WAF bot protection: $($_.Exception.Message)"
    }
}
