# =============================================================================
# Section 6: Management and Governance Services - Custom Check Functions
# CIS Microsoft Azure Foundations Benchmark v5.0.0
# =============================================================================
# Custom functions for diagnostic settings, monitoring alerts, and Application
# Insights controls. Dispatched via 'Custom' CheckPattern.
# Each function receives -ControlDef (hashtable) and -ResourceCache (hashtable).
# =============================================================================

function Test-CIS6111-SubscriptionDiagnostics {
    <#
    .SYNOPSIS
        CIS 6.1.1.1 - Ensure a 'Diagnostic Setting' exists for Subscription Activity Logs.
    .DESCRIPTION
        Checks that at least one subscription-level diagnostic setting is configured
        using Get-AzSubscriptionDiagnosticSetting.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $subId = (Get-AzContext -ErrorAction Stop).Subscription.Id
        $diagSettings = @(Get-AzSubscriptionDiagnosticSetting -SubscriptionId $subId -ErrorAction Stop)

        if ($diagSettings.Count -gt 0) {
            $settingNames = ($diagSettings | ForEach-Object { $_.Name }) -join ', '
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "Found $($diagSettings.Count) subscription diagnostic setting(s): $settingNames" `
                -TotalResources 1 -PassedResources 1 -FailedResources 0
        }

        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'FAIL' `
            -Details "No diagnostic settings configured for the subscription activity log." `
            -AffectedResources @("Subscription: $subId") `
            -TotalResources 1 -PassedResources 0 -FailedResources 1
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking subscription diagnostic settings: $(Format-CISErrorMessage -Message $_.Exception.Message)"
    }
}

function Test-CIS6112-DiagnosticCategories {
    <#
    .SYNOPSIS
        CIS 6.1.1.2 - Ensure Diagnostic Setting captures appropriate categories.
    .DESCRIPTION
        Checks that subscription diagnostic settings have Administrative, Alert,
        Policy, and Security categories enabled.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $requiredCategories = @('Administrative', 'Alert', 'Policy', 'Security')
        $subId = (Get-AzContext -ErrorAction Stop).Subscription.Id
        $diagSettings = @(Get-AzSubscriptionDiagnosticSetting -SubscriptionId $subId -ErrorAction Stop)

        if ($diagSettings.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details "No subscription diagnostic settings found. Required categories: $($requiredCategories -join ', ')" `
                -AffectedResources @("Subscription: $subId") `
                -TotalResources 1 -PassedResources 0 -FailedResources 1
        }

        # Check if at least one diagnostic setting covers all required categories
        $allCategoriesCovered = $false
        $bestCoverage         = @()

        foreach ($setting in $diagSettings) {
            $enabledCategories = @()
            # Support both $setting.Logs (newer Az.Monitor) and $setting.Log (older Az.Monitor)
            $logEntries = if ($setting.Logs) { $setting.Logs } elseif ($setting.Log) { $setting.Log } else { $null }
            if ($logEntries) {
                $enabledCategories = @($logEntries |
                    Where-Object { $_.Enabled -eq $true } |
                    ForEach-Object { $_.Category })
            }

            $missingForSetting = @($requiredCategories | Where-Object { $_ -notin $enabledCategories })
            if ($missingForSetting.Count -eq 0) {
                $allCategoriesCovered = $true
                break
            }

            if ($enabledCategories.Count -gt $bestCoverage.Count) {
                $bestCoverage = $enabledCategories
            }
        }

        if ($allCategoriesCovered) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "Subscription diagnostic settings capture all required categories: $($requiredCategories -join ', ')." `
                -TotalResources 1 -PassedResources 1 -FailedResources 0
        }

        $missingCategories = @($requiredCategories | Where-Object { $_ -notin $bestCoverage })
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'FAIL' `
            -Details "Subscription diagnostic settings do not capture all required categories. Missing: $($missingCategories -join ', '). Required: $($requiredCategories -join ', ')." `
            -AffectedResources @("Missing categories: $($missingCategories -join ', ')") `
            -TotalResources 1 -PassedResources 0 -FailedResources 1
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking diagnostic categories: $(Format-CISErrorMessage -Message $_.Exception.Message)"
    }
}

function Test-CIS6114-KeyVaultLogging {
    <#
    .SYNOPSIS
        CIS 6.1.1.4 - Ensure that logging for Azure Key Vault is 'Enabled'.
    .DESCRIPTION
        For each Key Vault, checks that a diagnostic setting exists with audit
        logs enabled.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $keyVaults = @($ResourceCache.KeyVaults)
        if ($keyVaults.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No Key Vaults found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $totalCount  = $keyVaults.Count
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        foreach ($kv in $keyVaults) {
            try {
                $resourceId = $kv.ResourceId
                if (-not $resourceId) {
                    # Build resource ID from available properties
                    $resourceId = "/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$($kv.ResourceGroupName)/providers/Microsoft.KeyVault/vaults/$($kv.VaultName)"
                }

                $diagSettings = @(Get-AzDiagnosticSetting -ResourceId $resourceId -ErrorAction Stop)

                if ($diagSettings.Count -eq 0) {
                    $failedList.Add("$($kv.VaultName) (no diagnostic settings)")
                    continue
                }

                # CIS requires both 'audit' and 'allLogs' category groups to be enabled.
                # Also accept the legacy 'AuditEvent' category for older Az.Monitor modules.
                $hasAudit   = $false
                $hasAllLogs = $false

                foreach ($setting in $diagSettings) {
                    # Support both $setting.Logs (newer Az.Monitor) and $setting.Log (older Az.Monitor)
                    $logEntries = if ($setting.Logs) { $setting.Logs } elseif ($setting.Log) { $setting.Log } else { $null }
                    if ($logEntries) {
                        $auditLog = $logEntries | Where-Object {
                            ($_.Category -eq 'AuditEvent' -or $_.Category -eq 'audit') -and $_.Enabled -eq $true
                        }
                        if ($auditLog) { $hasAudit = $true }
                    }
                    # Check category groups (newer approach)
                    if ($setting.LogCategoryGroup) {
                        foreach ($group in $setting.LogCategoryGroup) {
                            if ($group.Enabled -eq $true) {
                                if ($group.CategoryGroup -eq 'audit')   { $hasAudit   = $true }
                                if ($group.CategoryGroup -eq 'allLogs') { $hasAllLogs = $true }
                            }
                        }
                    }
                }

                if ($hasAudit -and $hasAllLogs) {
                    $passedCount++
                }
                elseif ($hasAudit) {
                    # audit is enabled but allLogs is not — partial compliance
                    $failedList.Add("$($kv.VaultName) (missing 'allLogs' category group)")
                }
                else {
                    $failedList.Add("$($kv.VaultName) (audit logs not enabled)")
                }
            }
            catch {
                $failedList.Add("$($kv.VaultName) [Error: $(Format-CISErrorMessage -Message $_.Exception.Message)]")
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount of $totalCount Key Vault(s) without proper audit logging: $($failedList -join '; ')"
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
            -Details "All $totalCount Key Vault(s) have audit logging enabled." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking Key Vault logging: $(Format-CISErrorMessage -Message $_.Exception.Message)"
    }
}

function Test-CIS6116-AppServiceHTTPLogs {
    <#
    .SYNOPSIS
        CIS 6.1.1.6 - Ensure that logging for Azure AppService 'HTTP logs' is enabled.
    .DESCRIPTION
        Gets App Services and checks that each has a diagnostic setting with HTTP
        logs enabled.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        # Retrieve web apps - use cache if available, otherwise fetch
        $webApps = @($ResourceCache.WebApps)
        if ($webApps.Count -eq 0) {
            try {
                $webApps = @(Get-AzWebApp -ErrorAction Stop)
            }
            catch {
                return New-CISCheckResult `
                    -ControlId $ControlDef.ControlId `
                    -Title $ControlDef.Title `
                    -Status 'ERROR' `
                    -Details "Failed to retrieve App Services: $(Format-CISErrorMessage -Message $_.Exception.Message)"
            }
        }

        if ($webApps.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No App Services found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $totalCount  = $webApps.Count
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        foreach ($app in $webApps) {
            try {
                $diagSettings = @(Get-AzDiagnosticSetting -ResourceId $app.Id -ErrorAction Stop)

                if ($diagSettings.Count -eq 0) {
                    $failedList.Add("$($app.Name) (no diagnostic settings)")
                    continue
                }

                $hasHttpLogs = $false
                foreach ($setting in $diagSettings) {
                    # Support both $setting.Logs (newer Az.Monitor) and $setting.Log (older Az.Monitor)
                    $logEntries = if ($setting.Logs) { $setting.Logs } elseif ($setting.Log) { $setting.Log } else { $null }
                    if ($logEntries) {
                        $httpLog = $logEntries | Where-Object {
                            ($_.Category -eq 'AppServiceHTTPLogs' -or $_.Category -eq 'HttpLogs') -and $_.Enabled -eq $true
                        }
                        if ($httpLog) {
                            $hasHttpLogs = $true
                            break
                        }
                    }
                    if ($setting.LogCategoryGroup) {
                        $logGroup = $setting.LogCategoryGroup | Where-Object {
                            $_.CategoryGroup -eq 'allLogs' -and $_.Enabled -eq $true
                        }
                        if ($logGroup) {
                            $hasHttpLogs = $true
                            break
                        }
                    }
                }

                if ($hasHttpLogs) {
                    $passedCount++
                }
                else {
                    $failedList.Add("$($app.Name) (HTTP logs not enabled)")
                }
            }
            catch {
                $failedList.Add("$($app.Name) [Error: $(Format-CISErrorMessage -Message $_.Exception.Message)]")
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount of $totalCount App Service(s) without HTTP logging: $($failedList -join '; ')"
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
            -Details "All $totalCount App Service(s) have HTTP logging enabled." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking App Service HTTP logs: $(Format-CISErrorMessage -Message $_.Exception.Message)"
    }
}

function Test-CIS61211-ServiceHealthAlert {
    <#
    .SYNOPSIS
        CIS 6.1.2.11 - Ensure an Activity Log Alert exists for Service Health.
    .DESCRIPTION
        Checks for activity log alerts where the category is 'ServiceHealth',
        which monitors Azure service issues, planned maintenance, and security
        advisories.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $alerts = @($ResourceCache.ActivityLogAlerts)

        if ($alerts.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details "No activity log alerts found in the subscription. A Service Health alert is required." `
                -TotalResources 0 -PassedResources 0 -FailedResources 1
        }

        $serviceHealthAlerts = [System.Collections.Generic.List[string]]::new()

        foreach ($alert in $alerts) {
            if (-not $alert.Enabled) { continue }

            $isServiceHealth = $false

            # Check conditions/allOf for category = ServiceHealth
            $conditions = $null
            if ($alert.Condition -and $alert.Condition.AllOf) {
                $conditions = $alert.Condition.AllOf
            }
            elseif ($alert.ConditionAllOf) {
                $conditions = $alert.ConditionAllOf
            }

            if ($conditions) {
                foreach ($condition in $conditions) {
                    $field  = if ($condition.Field) { $condition.Field } else { $condition.field }
                    $equals = if ($condition.Equals) { $condition.Equals } else { $condition.equals }

                    if ($field -eq 'category' -and $equals -eq 'ServiceHealth') {
                        $isServiceHealth = $true
                        break
                    }
                }
            }

            if ($isServiceHealth) {
                $serviceHealthAlerts.Add($alert.Name)
            }
        }

        if ($serviceHealthAlerts.Count -gt 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "Found $($serviceHealthAlerts.Count) Service Health alert(s): $($serviceHealthAlerts -join ', ')" `
                -TotalResources $serviceHealthAlerts.Count `
                -PassedResources $serviceHealthAlerts.Count `
                -FailedResources 0
        }

        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'FAIL' `
            -Details "No activity log alert found with category 'ServiceHealth'. $($alerts.Count) alert(s) were checked." `
            -AffectedResources @("No Service Health alert configured") `
            -TotalResources $alerts.Count -PassedResources 0 -FailedResources 1
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking Service Health alerts: $(Format-CISErrorMessage -Message $_.Exception.Message)"
    }
}

function Test-CIS6131-ApplicationInsights {
    <#
    .SYNOPSIS
        CIS 6.1.3.1 - Ensure Application Insights are Configured.
    .DESCRIPTION
        Checks if Application Insights resources exist in the subscription via
        Get-AzResource for microsoft.insights/components.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $appInsights = @(Get-AzResource -ResourceType 'microsoft.insights/components' -ErrorAction Stop)

        if ($appInsights.Count -gt 0) {
            $names = ($appInsights | ForEach-Object { $_.Name }) -join ', '
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "Found $($appInsights.Count) Application Insights resource(s): $names" `
                -TotalResources $appInsights.Count `
                -PassedResources $appInsights.Count `
                -FailedResources 0
        }

        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'FAIL' `
            -Details "No Application Insights resources found in the subscription. Application monitoring should be configured." `
            -AffectedResources @("No Application Insights configured") `
            -TotalResources 0 -PassedResources 0 -FailedResources 1
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking Application Insights: $(Format-CISErrorMessage -Message $_.Exception.Message)"
    }
}
