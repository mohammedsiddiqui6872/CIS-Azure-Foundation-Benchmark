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
        # Check Az module
        $azContext = $null
        try {
            $azContext = Get-AzContext -ErrorAction Stop
        }
        catch {
            $envInfo.IsValid = $false
            $envInfo.Errors += "Azure PowerShell is not connected. Run 'Connect-AzAccount' first."
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

        # Check Graph module if needed
        if ($envInfo.NeedsGraph) {
            try {
                $graphContext = Get-MgContext -ErrorAction Stop
                if ($graphContext) {
                    $envInfo.GraphConnected = $true
                    if (-not $envInfo.TenantDomain -and $graphContext.TenantId) {
                        $envInfo.TenantDomain = $graphContext.TenantId
                    }

                    # Validate required Graph scopes
                    $requiredScopes = @('Policy.Read.All', 'Directory.Read.All')
                    $optionalScopes = @('UserAuthenticationMethod.Read.All', 'Reports.Read.All')
                    $currentScopes = @($graphContext.Scopes)

                    $missingRequired = @($requiredScopes | Where-Object { $_ -notin $currentScopes })
                    $missingOptional = @($optionalScopes | Where-Object { $_ -notin $currentScopes })

                    if ($missingRequired.Count -gt 0) {
                        $envInfo.Warnings += "Microsoft Graph is connected but missing required scopes: $($missingRequired -join ', '). Some identity checks may fail. Reconnect with: Connect-MgGraph -Scopes $($requiredScopes -join ',')"
                    }
                    if ($missingOptional.Count -gt 0) {
                        $envInfo.Warnings += "Microsoft Graph is missing optional scopes: $($missingOptional -join ', '). MFA registration checks may use fallback methods. For full accuracy: Connect-MgGraph -Scopes $(@($requiredScopes + $optionalScopes) -join ',')"
                    }
                }
                else {
                    $envInfo.Warnings += "Microsoft Graph is not connected. Identity checks (Section 5) will return ERROR. Run 'Connect-MgGraph -Scopes Policy.Read.All,Directory.Read.All,UserAuthenticationMethod.Read.All' to enable."
                }
            }
            catch {
                $envInfo.Warnings += "Microsoft Graph module not available. Identity checks (Section 5) will return ERROR. Install with: Install-Module Microsoft.Graph.Identity.SignIns"
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
        catch { }
    }

    return $envInfo
}
