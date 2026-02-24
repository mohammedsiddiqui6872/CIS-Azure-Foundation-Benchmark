function Install-CISRequiredModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ModuleName,

        [Parameter()]
        [string]$MinimumVersion
    )

    $installed = Get-Module -ListAvailable -Name $ModuleName -ErrorAction SilentlyContinue
    if ($MinimumVersion) {
        $installed = $installed | Where-Object { $_.Version -ge [version]$MinimumVersion }
    }

    if ($installed) { return $true }

    Write-Host "  Required module '$ModuleName' not found. Installing..." -ForegroundColor Yellow
    try {
        $installParams = @{
            Name               = $ModuleName
            Scope              = 'CurrentUser'
            Force              = $true
            AllowClobber       = $true
            ErrorAction        = 'Stop'
        }
        if ($MinimumVersion) { $installParams.MinimumVersion = $MinimumVersion }
        Install-Module @installParams
        Write-Host "  Installed '$ModuleName' successfully." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Warning "  Failed to install '$ModuleName': $($_.Exception.Message)"
        return $false
    }
}

function Initialize-CISEnvironment {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$SubscriptionId,

        [Parameter()]
        [switch]$SkipModuleCheck,

        [Parameter()]
        [hashtable[]]$ControlsToRun
    )

    $envInfo = @{
        IsValid           = $true
        Errors            = @()
        Warnings          = @()
        SubscriptionId    = ''
        SubscriptionName  = ''
        TenantId          = ''
        TenantDomain      = ''
        NeedsGraph        = $false
        GraphConnected    = $false
        ScanTimestamp     = [DateTime]::UtcNow.ToString('o')
    }

    # Check if Graph is needed (Section 5 identity checks)
    $graphPatterns = @('GraphAPIProperty')
    $graphSections = @('Identity Services')
    $envInfo.NeedsGraph = ($ControlsToRun | Where-Object {
        $_.CheckPattern -in $graphPatterns -or $_.Section -in $graphSections
    }).Count -gt 0

    if (-not $SkipModuleCheck) {
        # --- Check and install required modules ---
        Write-Host "`n  Checking required modules..." -ForegroundColor Cyan

        $requiredAzModules = @(
            @{ Name = 'Az.Accounts';   MinVersion = '2.0.0' }
            @{ Name = 'Az.Security';   MinVersion = '1.0.0' }
            @{ Name = 'Az.Network';    MinVersion = '4.0.0' }
            @{ Name = 'Az.Storage';    MinVersion = '4.0.0' }
            @{ Name = 'Az.KeyVault';   MinVersion = '4.0.0' }
            @{ Name = 'Az.Monitor';    MinVersion = '3.0.0' }
            @{ Name = 'Az.Resources';  MinVersion = '5.0.0' }
            @{ Name = 'Az.Websites';   MinVersion = '2.0.0' }
            @{ Name = 'Az.Databricks'; MinVersion = '1.0.0' }
        )

        $graphModules = @(
            @{ Name = 'Microsoft.Graph.Authentication'; MinVersion = '' }
            @{ Name = 'Microsoft.Graph.Identity.SignIns'; MinVersion = '' }
            @{ Name = 'Microsoft.Graph.Users'; MinVersion = '' }
        )

        $allInstalled = $true
        foreach ($mod in $requiredAzModules) {
            if (-not (Install-CISRequiredModule -ModuleName $mod.Name -MinimumVersion $mod.MinVersion)) {
                $envInfo.Errors += "Required module '$($mod.Name)' is not installed and could not be auto-installed. Run: Install-Module $($mod.Name) -Scope CurrentUser"
                $allInstalled = $false
            }
        }

        if ($envInfo.NeedsGraph) {
            foreach ($mod in $graphModules) {
                if (-not (Install-CISRequiredModule -ModuleName $mod.Name -MinimumVersion $mod.MinVersion)) {
                    $envInfo.Warnings += "Graph module '$($mod.Name)' is not installed. Identity checks (Section 5) may fail. Run: Install-Module $($mod.Name) -Scope CurrentUser"
                }
            }
        }

        if (-not $allInstalled) {
            $envInfo.IsValid = $false
            return $envInfo
        }

        Write-Host "  All required modules are available." -ForegroundColor Green

        # --- Check and auto-connect to Azure ---
        $azContext = $null
        try {
            $azContext = Get-AzContext -ErrorAction Stop
        }
        catch {
            $azContext = $null
        }

        if (-not $azContext -or -not $azContext.Subscription) {
            Write-Host "`n  Azure is not connected. Launching interactive login..." -ForegroundColor Yellow
            try {
                Connect-AzAccount -ErrorAction Stop | Out-Null
                $azContext = Get-AzContext -ErrorAction Stop
                Write-Host "  Azure connected successfully." -ForegroundColor Green
            }
            catch {
                $envInfo.IsValid = $false
                $envInfo.Errors += "Failed to connect to Azure: $($_.Exception.Message)"
                return $envInfo
            }
        }

        if ($azContext) {
            if ($SubscriptionId) {
                try {
                    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
                    $azContext = Get-AzContext
                }
                catch {
                    $envInfo.IsValid = $false
                    $envInfo.Errors += "Failed to set subscription '$SubscriptionId': $($_.Exception.Message)"
                }
            }
            $envInfo.SubscriptionId   = $azContext.Subscription.Id
            $envInfo.SubscriptionName = $azContext.Subscription.Name
            $envInfo.TenantId         = $azContext.Tenant.Id
        }

        # --- Check and auto-connect to Microsoft Graph if needed ---
        if ($envInfo.NeedsGraph) {
            $graphConnected = $false
            $allScopes = @('Policy.Read.All', 'Directory.Read.All', 'UserAuthenticationMethod.Read.All', 'Reports.Read.All')

            try {
                $graphContext = Get-MgContext -ErrorAction Stop
                if ($graphContext) {
                    $graphConnected = $true
                    $currentScopes = @($graphContext.Scopes)

                    # Check if all required scopes are present
                    $missingScopes = @($allScopes | Where-Object { $_ -notin $currentScopes })
                    if ($missingScopes.Count -gt 0) {
                        Write-Host "  Graph is connected but missing scopes: $($missingScopes -join ', '). Reconnecting..." -ForegroundColor Yellow
                        $graphConnected = $false
                    }
                }
            }
            catch {
                $graphConnected = $false
            }

            if (-not $graphConnected) {
                Write-Host "`n  Connecting to Microsoft Graph for Identity checks..." -ForegroundColor Yellow
                try {
                    Connect-MgGraph -Scopes $allScopes -ErrorAction Stop -NoWelcome | Out-Null
                    $graphContext = Get-MgContext -ErrorAction Stop
                    $graphConnected = $true
                    Write-Host "  Microsoft Graph connected successfully." -ForegroundColor Green
                }
                catch {
                    $envInfo.Warnings += "Could not connect to Microsoft Graph: $($_.Exception.Message). Identity checks (Section 5) will return ERROR."
                }
            }

            if ($graphConnected) {
                $envInfo.GraphConnected = $true
            }
        }
    }
    else {
        # Skip checks but still get context
        try {
            $azContext = Get-AzContext -ErrorAction SilentlyContinue
            if ($azContext) {
                $envInfo.SubscriptionId   = $azContext.Subscription.Id
                $envInfo.SubscriptionName = $azContext.Subscription.Name
                $envInfo.TenantId         = $azContext.Tenant.Id
            }
        }
        catch { Write-Verbose "Could not retrieve Azure context: $($_.Exception.Message)" }
    }

    return $envInfo
}
