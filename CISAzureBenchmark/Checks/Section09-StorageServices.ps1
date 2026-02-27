# =============================================================================
# Section 9: Storage Services - Custom Check Functions
# CIS Microsoft Azure Foundations Benchmark v5.0.0
# =============================================================================
# Custom functions for storage account key management, private endpoints,
# trusted services, and redundancy controls.
# Dispatched via 'Custom' CheckPattern.
# Each function receives -ControlDef (hashtable) and -ResourceCache (hashtable).
# =============================================================================

function Test-CIS9311-KeyRotationReminders {
    <#
    .SYNOPSIS
        CIS 9.3.1.1 - Ensure 'Enable key rotation reminders' is enabled for each Storage Account.
    .DESCRIPTION
        Checks each storage account for key rotation reminder policy (KeyPolicy
        with KeyExpirationPeriodInDays configured).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $storageAccounts = @($ResourceCache.StorageAccounts)
        if ($storageAccounts.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No storage accounts found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $totalCount  = $storageAccounts.Count
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        foreach ($sa in $storageAccounts) {
            $hasKeyPolicy = $false

            # Check KeyPolicy for expiration period
            if ($sa.KeyPolicy -and $sa.KeyPolicy.KeyExpirationPeriodInDays) {
                if ($sa.KeyPolicy.KeyExpirationPeriodInDays -gt 0) {
                    $hasKeyPolicy = $true
                }
            }

            if ($hasKeyPolicy) {
                $passedCount++
            }
            else {
                $failedList.Add("$($sa.StorageAccountName) (RG: $($sa.ResourceGroupName))")
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount of $totalCount storage account(s) without key rotation reminders: $($failedList -join '; ')"
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
            -Details "All $totalCount storage account(s) have key rotation reminders configured." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        $status = if ($_.Exception.Message -match 'AuthorizationFailed|does not have authorization') { 'WARNING' } else { 'ERROR' }
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status $status `
            -Details "$(if ($status -eq 'WARNING') { 'Insufficient permissions' } else { 'Error' }) checking key rotation reminders: $(Format-CISErrorMessage $_.Exception.Message)"
    }
}

function Test-CIS9312-KeyRegeneration {
    <#
    .SYNOPSIS
        CIS 9.3.1.2 - Ensure Storage Account access keys are periodically regenerated.
    .DESCRIPTION
        Checks storage account key creation time to verify keys have been
        regenerated within the configured period (default 90 days, configurable via CISConfig.KeyRotationMaxDays).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $storageAccounts = @($ResourceCache.StorageAccounts)
        if ($storageAccounts.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No storage accounts found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $maxAgeDays  = if ($script:CISConfig.KeyRotationMaxDays) { $script:CISConfig.KeyRotationMaxDays } else { 90 }
        $now         = [DateTime]::UtcNow
        $totalCount  = $storageAccounts.Count
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        foreach ($sa in $storageAccounts) {
            if ($sa.KeyCreationTime) {
                # Check both key1 and key2 creation times
                $key1Time = $sa.KeyCreationTime.Key1
                $key2Time = $sa.KeyCreationTime.Key2

                # Only evaluate keys that have valid timestamps
                $key1AgeDays = if ($key1Time) { ($now - $key1Time).TotalDays } else { $null }
                $key2AgeDays = if ($key2Time) { ($now - $key2Time).TotalDays } else { $null }

                $key1Old = ($null -ne $key1AgeDays) -and ($key1AgeDays -gt $maxAgeDays)
                $key2Old = ($null -ne $key2AgeDays) -and ($key2AgeDays -gt $maxAgeDays)
                $bothUnknown = ($null -eq $key1AgeDays) -and ($null -eq $key2AgeDays)

                if ($bothUnknown) {
                    $failedList.Add("$($sa.StorageAccountName) (key creation times unavailable)")
                }
                elseif ($key1Old -or $key2Old) {
                    $ages = @()
                    if ($null -ne $key1AgeDays) { $ages += $key1AgeDays }
                    if ($null -ne $key2AgeDays) { $ages += $key2AgeDays }
                    $oldestDays = ($ages | Measure-Object -Maximum).Maximum
                    $failedList.Add("$($sa.StorageAccountName) (oldest key: $([math]::Floor($oldestDays)) days)")
                }
                else {
                    $passedCount++
                }
            }
            else {
                # KeyCreationTime not available - cannot determine key age
                $failedList.Add("$($sa.StorageAccountName) (key creation time unavailable)")
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount of $totalCount storage account(s) with keys older than $maxAgeDays days: $($failedList -join '; ')"
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
            -Details "All $totalCount storage account(s) have keys regenerated within the last $maxAgeDays days." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        $status = if ($_.Exception.Message -match 'AuthorizationFailed|does not have authorization') { 'WARNING' } else { 'ERROR' }
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status $status `
            -Details "$(if ($status -eq 'WARNING') { 'Insufficient permissions' } else { 'Error' }) checking key regeneration: $(Format-CISErrorMessage $_.Exception.Message)"
    }
}

function Test-CIS9321-StoragePrivateEndpoints {
    <#
    .SYNOPSIS
        CIS 9.3.2.1 - Ensure Private Endpoints are used to access Storage Accounts.
    .DESCRIPTION
        Checks each storage account for the existence of private endpoint connections.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $storageAccounts = @($ResourceCache.StorageAccounts)
        if ($storageAccounts.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No storage accounts found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $totalCount  = $storageAccounts.Count
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        foreach ($sa in $storageAccounts) {
            $hasPrivateEndpoints = $false

            # Check PrivateEndpointConnections property
            if ($sa.PrivateEndpointConnections -and $sa.PrivateEndpointConnections.Count -gt 0) {
                $hasPrivateEndpoints = $true
            }

            # Alternative: check via NetworkRuleSet for virtual network rules (not the same as PE but indicates private access)
            if (-not $hasPrivateEndpoints) {
                try {
                    $saResource = Get-AzResource -ResourceId $sa.Id -ExpandProperties -ErrorAction Stop
                    if ($saResource.Properties.privateEndpointConnections -and $saResource.Properties.privateEndpointConnections.Count -gt 0) {
                        $hasPrivateEndpoints = $true
                    }
                }
                catch {
                    Write-Verbose "Could not expand properties for $($sa.StorageAccountName): $($_.Exception.Message)"
                }
            }

            if ($hasPrivateEndpoints) {
                $passedCount++
            }
            else {
                $failedList.Add("$($sa.StorageAccountName) (RG: $($sa.ResourceGroupName))")
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount of $totalCount storage account(s) without private endpoints: $($failedList -join '; ')"
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
            -Details "All $totalCount storage account(s) have private endpoints configured." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        $status = if ($_.Exception.Message -match 'AuthorizationFailed|does not have authorization') { 'WARNING' } else { 'ERROR' }
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status $status `
            -Details "$(if ($status -eq 'WARNING') { 'Insufficient permissions' } else { 'Error' }) checking storage private endpoints: $(Format-CISErrorMessage $_.Exception.Message)"
    }
}

function Test-CIS935-TrustedServices {
    <#
    .SYNOPSIS
        CIS 9.3.5 - Ensure 'Allow Azure services on the trusted services list' is Enabled.
    .DESCRIPTION
        Checks each storage account's network rules to verify the bypass includes
        'AzureServices'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $storageAccounts = @($ResourceCache.StorageAccounts)
        if ($storageAccounts.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No storage accounts found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $totalCount  = $storageAccounts.Count
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        foreach ($sa in $storageAccounts) {
            $bypassTrusted = $false

            if ($sa.NetworkRuleSet -and $sa.NetworkRuleSet.Bypass) {
                $bypass = $sa.NetworkRuleSet.Bypass.ToString()
                if ($bypass -match 'AzureServices') {
                    $bypassTrusted = $true
                }
            }

            # Note: DefaultAction='Allow' permits ALL traffic, not just trusted services.
            # CIS 9.3.5 requires explicit Bypass='AzureServices' regardless of DefaultAction.

            if ($bypassTrusted) {
                $passedCount++
            }
            else {
                $currentBypass = if ($sa.NetworkRuleSet -and $sa.NetworkRuleSet.Bypass) {
                    $sa.NetworkRuleSet.Bypass.ToString()
                } else { 'None' }
                $failedList.Add("$($sa.StorageAccountName) (Bypass: $currentBypass)")
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount of $totalCount storage account(s) not allowing trusted Azure services: $($failedList -join '; ')"
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
            -Details "All $totalCount storage account(s) allow trusted Azure services." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        $status = if ($_.Exception.Message -match 'AuthorizationFailed|does not have authorization') { 'WARNING' } else { 'ERROR' }
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status $status `
            -Details "$(if ($status -eq 'WARNING') { 'Insufficient permissions' } else { 'Error' }) checking trusted services: $(Format-CISErrorMessage $_.Exception.Message)"
    }
}

function Test-CIS9311-StorageRedundancy {
    <#
    .SYNOPSIS
        CIS 9.3.11 - Ensure Redundancy is set to GRS on critical Azure Storage Accounts.
    .DESCRIPTION
        Checks each storage account SKU for geo-redundant storage (GRS, RA-GRS,
        GZRS, or RA-GZRS).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $storageAccounts = @($ResourceCache.StorageAccounts)
        if ($storageAccounts.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No storage accounts found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        # Geo-redundant SKU names
        $geoRedundantSkus = @(
            'Standard_GRS',
            'Standard_RAGRS',
            'Standard_GZRS',
            'Standard_RAGZRS'
        )

        $totalCount  = $storageAccounts.Count
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        foreach ($sa in $storageAccounts) {
            $skuName = $null
            if ($sa.Sku -and $sa.Sku.Name) {
                $skuName = $sa.Sku.Name
            }

            if ($skuName -and $skuName -in $geoRedundantSkus) {
                $passedCount++
            }
            else {
                $currentSku = if ($skuName) { $skuName } else { 'Unknown' }
                $failedList.Add("$($sa.StorageAccountName) (SKU: $currentSku)")
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount of $totalCount storage account(s) without geo-redundant storage: $($failedList -join '; ')"
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
            -Details "All $totalCount storage account(s) use geo-redundant storage." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        $status = if ($_.Exception.Message -match 'AuthorizationFailed|does not have authorization') { 'WARNING' } else { 'ERROR' }
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status $status `
            -Details "$(if ($status -eq 'WARNING') { 'Insufficient permissions' } else { 'Error' }) checking storage redundancy: $(Format-CISErrorMessage $_.Exception.Message)"
    }
}
