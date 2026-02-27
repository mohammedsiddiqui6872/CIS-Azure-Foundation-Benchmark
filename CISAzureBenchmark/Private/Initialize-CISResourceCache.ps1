function Initialize-CISResourceCache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable[]]$ControlsToRun,

        [Parameter()]
        [hashtable]$ExcludeResourceTag
    )

    $cache = @{
        NSGs                 = @()
        StorageAccounts      = @()
        KeyVaults            = @()
        KeyVaultDetails      = @{}
        ActivityLogAlerts    = @()
        ApplicationGateways  = @()
        NetworkWatchers      = @()
        VirtualNetworks      = @()
        DatabricksWorkspaces = @()
        WafPolicies          = @{}
        BlobServiceProperties = @{}
        FileServiceProperties = @{}
        FetchWarnings        = [System.Collections.Generic.List[string]]::new()
        FailedResourceTypes  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }

    $patterns = $ControlsToRun | ForEach-Object { $_.CheckPattern } | Select-Object -Unique
    $sections = $ControlsToRun | ForEach-Object { $_.Section } | Select-Object -Unique

    # Helper to fetch resources with retry logic
    function Invoke-CacheFetch {
        param(
            [string]$ResourceType,
            [scriptblock]$FetchScript
        )
        Write-CISProgress -Activity "Pre-fetching resources" -Status "$ResourceType..."
        try {
            $result = @(Invoke-WithRetry -ScriptBlock $FetchScript -OperationName "Fetch $ResourceType")
            Write-Verbose "Cached $($result.Count) $ResourceType"
            return $result
        }
        catch {
            $warnMsg = "Failed to fetch ${ResourceType}: $(Format-CISErrorMessage -Message $_.Exception.Message). Checks depending on this resource type may report inaccurate results."
            Write-Warning $warnMsg
            $cache.FetchWarnings.Add($warnMsg)
            [void]$cache.FailedResourceTypes.Add($ResourceType)
            return @()
        }
    }

    # Storage accounts - needed by many checks
    if ($patterns | Where-Object { $_ -in @('StorageAccountProperty', 'StorageBlobProperty', 'StorageFileProperty', 'Custom') }) {
        $cache.StorageAccounts = Invoke-CacheFetch -ResourceType 'Storage Accounts' -FetchScript {
            Get-AzStorageAccount -ErrorAction Stop
        }

        # Pre-fetch blob and file service properties for cached storage accounts
        if ($cache.StorageAccounts.Count -gt 0) {
            Write-Verbose "Pre-fetching blob/file service properties for $($cache.StorageAccounts.Count) storage accounts..."
            foreach ($sa in $cache.StorageAccounts) {
                try {
                    $ctx = $sa | New-AzStorageContext -ErrorAction Stop
                    try {
                        $cache.BlobServiceProperties[$sa.StorageAccountName] = Invoke-WithRetry -OperationName "Blob properties for $($sa.StorageAccountName)" -ScriptBlock {
                            Get-AzStorageBlobServiceProperty -StorageContext $ctx -ErrorAction Stop
                        }
                    } catch { Write-Verbose "Could not get blob properties for $($sa.StorageAccountName): $($_.Exception.Message)" }
                    try {
                        $cache.FileServiceProperties[$sa.StorageAccountName] = Invoke-WithRetry -OperationName "File properties for $($sa.StorageAccountName)" -ScriptBlock {
                            Get-AzStorageFileServiceProperty -StorageContext $ctx -ErrorAction Stop
                        }
                    } catch { Write-Verbose "Could not get file properties for $($sa.StorageAccountName): $($_.Exception.Message)" }
                } catch { Write-Verbose "Could not create storage context for $($sa.StorageAccountName): $($_.Exception.Message)" }
            }
        }
    }

    # Network Security Groups
    if ($patterns -contains 'NSGPortCheck' -or $sections -contains 'Networking Services') {
        $cache.NSGs = Invoke-CacheFetch -ResourceType 'Network Security Groups' -FetchScript {
            Get-AzNetworkSecurityGroup -ErrorAction Stop
        }
    }

    # Key Vaults - needed by KeyVault patterns and custom checks
    if (($patterns | Where-Object { $_ -in @('KeyVaultProperty', 'KeyVaultKeyExpiry', 'KeyVaultSecretExpiry') }) -or
        ($ControlsToRun | Where-Object { $_.Subsection -eq 'Key Vault' -or $_.CheckFunction -match 'KeyVault' })) {
        $cache.KeyVaults = Invoke-CacheFetch -ResourceType 'Key Vaults' -FetchScript {
            Get-AzKeyVault -ErrorAction Stop
        }

        # After fetching Key Vaults list, pre-fetch full details to eliminate N+1 API calls
        if ($cache.KeyVaults.Count -gt 0) {
            Write-Verbose "Pre-fetching Key Vault details for $($cache.KeyVaults.Count) vaults..."
            foreach ($kv in $cache.KeyVaults) {
                try {
                    $fullVault = Get-AzKeyVault -VaultName $kv.VaultName -ResourceGroupName $kv.ResourceGroupName -ErrorAction Stop
                    $cache.KeyVaultDetails[$kv.VaultName] = $fullVault
                } catch {
                    Write-Verbose "Could not get details for vault $($kv.VaultName): $($_.Exception.Message)"
                }
            }
        }
    }

    # Activity Log Alerts
    if ($patterns -contains 'ActivityLogAlert') {
        $cache.ActivityLogAlerts = Invoke-CacheFetch -ResourceType 'Activity Log Alerts' -FetchScript {
            Get-AzActivityLogAlert -ErrorAction Stop
        }
    }

    # Networking resources
    if ($sections -contains 'Networking Services') {
        $cache.ApplicationGateways = Invoke-CacheFetch -ResourceType 'Application Gateways' -FetchScript {
            Get-AzApplicationGateway -ErrorAction Stop
        }

        $cache.VirtualNetworks = Invoke-CacheFetch -ResourceType 'Virtual Networks' -FetchScript {
            Get-AzVirtualNetwork -ErrorAction Stop
        }

        $cache.NetworkWatchers = Invoke-CacheFetch -ResourceType 'Network Watchers' -FetchScript {
            Get-AzNetworkWatcher -ErrorAction Stop
        }

        # Pre-fetch WAF policies from Application Gateways to avoid duplicate API calls
        if ($cache.ApplicationGateways.Count -gt 0) {
            $wafPolicyIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($gw in $cache.ApplicationGateways) {
                if ($gw.FirewallPolicy -and $gw.FirewallPolicy.Id) {
                    [void]$wafPolicyIds.Add($gw.FirewallPolicy.Id)
                }
            }
            foreach ($policyId in $wafPolicyIds) {
                try {
                    $policy = Get-AzResource -ResourceId $policyId -ExpandProperties -ErrorAction Stop
                    $cache.WafPolicies[$policyId] = $policy
                } catch {
                    Write-Verbose "Could not get WAF policy $policyId`: $($_.Exception.Message)"
                }
            }
        }
    }

    # Databricks Workspaces
    if ($sections -contains 'Analytics Services') {
        $cache.DatabricksWorkspaces = Invoke-CacheFetch -ResourceType 'Databricks Workspaces' -FetchScript {
            Get-AzDatabricksWorkspace -ErrorAction Stop
        }
    }

    Write-CISProgress -Activity "Pre-fetching resources" -Status "Complete" -PercentComplete 100

    # Apply tag-based exclusions if specified
    if ($ExcludeResourceTag -and $ExcludeResourceTag.Count -gt 0) {
        $tagFilterScript = {
            param($resource)
            if (-not $resource.Tags) { return $false }
            foreach ($tagKey in $ExcludeResourceTag.Keys) {
                if ($resource.Tags.ContainsKey($tagKey) -and $resource.Tags[$tagKey] -eq $ExcludeResourceTag[$tagKey]) {
                    return $true
                }
            }
            return $false
        }
        $excludableKeys = @('NSGs', 'StorageAccounts', 'KeyVaults', 'ApplicationGateways', 'VirtualNetworks', 'DatabricksWorkspaces')
        foreach ($key in $excludableKeys) {
            if ($cache[$key] -and $cache[$key].Count -gt 0) {
                $before = $cache[$key].Count
                $cache[$key] = @($cache[$key] | Where-Object { -not (& $tagFilterScript $_) })
                $excluded = $before - $cache[$key].Count
                if ($excluded -gt 0) {
                    Write-Verbose "Excluded $excluded $key resource(s) by tag filter"
                }
            }
        }
    }

    return $cache
}
