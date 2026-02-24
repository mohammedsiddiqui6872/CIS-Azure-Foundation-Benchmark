function Initialize-CISResourceCache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable[]]$ControlsToRun
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
        Subscriptions        = @()
        DiagnosticSettings   = @{}
        WebApps              = @()
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
            Write-Warning "Failed to fetch ${ResourceType}: $($_.Exception.Message)"
            return @()
        }
    }

    # Storage accounts - needed by many checks
    if ($patterns | Where-Object { $_ -in @('StorageAccountProperty', 'StorageBlobProperty', 'StorageFileProperty', 'Custom') }) {
        $cache.StorageAccounts = Invoke-CacheFetch -ResourceType 'Storage Accounts' -FetchScript {
            Get-AzStorageAccount -ErrorAction Stop
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
    }

    # Databricks Workspaces
    if ($sections -contains 'Analytics Services') {
        $cache.DatabricksWorkspaces = Invoke-CacheFetch -ResourceType 'Databricks Workspaces' -FetchScript {
            Get-AzDatabricksWorkspace -ErrorAction Stop
        }
    }

    Write-CISProgress -Activity "Pre-fetching resources" -Status "Complete" -PercentComplete 100

    return $cache
}
