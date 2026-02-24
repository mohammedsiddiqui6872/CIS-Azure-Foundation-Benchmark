# CommonPatterns.ps1
# Reusable pattern handler functions for CIS Azure Foundation Benchmark v5.0.0
# Each function receives a $ControlDef hashtable and optional cached resources,
# returning a result object via New-CISCheckResult.

#region 1. Invoke-DefenderPlanCheck

function Invoke-DefenderPlanCheck {
    <#
    .SYNOPSIS
        Checks if a Microsoft Defender plan is enabled at the expected pricing tier.
    .DESCRIPTION
        Uses Get-AzSecurityPricing to verify the specified Defender plan is set to the expected tier (typically 'Standard').
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef
    )

    try {
        $planName    = $ControlDef.DefenderPlanName
        $expected    = $ControlDef.ExpectedTier

        $pricing = Get-AzSecurityPricing -Name $planName -ErrorAction Stop

        if ($pricing.PricingTier -eq $expected) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "Defender plan '$planName' is set to '$($pricing.PricingTier)'." `
                -TotalResources 1 `
                -PassedResources 1 `
                -FailedResources 0
        }
        else {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details "Defender plan '$planName' is set to '$($pricing.PricingTier)'; expected '$expected'." `
                -AffectedResources @("DefenderPlan:$planName") `
                -TotalResources 1 `
                -PassedResources 0 `
                -FailedResources 1
        }
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Failed to query Defender plan '$($ControlDef.DefenderPlanName)': $($_.Exception.Message)"
    }
}

#endregion

#region 2. Invoke-ActivityLogAlertCheck

function Invoke-ActivityLogAlertCheck {
    <#
    .SYNOPSIS
        Checks whether an enabled Activity Log Alert exists for a specified operation name.
    .DESCRIPTION
        Searches cached activity log alerts for one whose conditions include the target OperationName.
        Handles both legacy (ConditionAllOf) and current (Condition.AllOf) Az.Monitor module property names.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter()]
        [object[]]$CachedAlerts = @()
    )

    try {
        $targetOperation = $ControlDef.OperationName

        if ($null -eq $CachedAlerts -or $CachedAlerts.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details "No activity log alerts found in the subscription. Expected an alert for '$targetOperation'." `
                -TotalResources 0 `
                -PassedResources 0 `
                -FailedResources 1
        }

        $matchFound = $false

        foreach ($alert in $CachedAlerts) {
            # Skip disabled alerts
            $isEnabled = $true
            if ($null -ne $alert.Enabled) {
                $isEnabled = $alert.Enabled
            }
            if (-not $isEnabled) { continue }

            # Collect all condition entries - handle both old and new property structures
            $conditions = @()

            # New Az.Monitor module: Condition.AllOf
            if ($alert.Condition -and $alert.Condition.AllOf) {
                $conditions = @($alert.Condition.AllOf)
            }
            # Legacy Az.Monitor module: ConditionAllOf
            elseif ($alert.ConditionAllOf) {
                $conditions = @($alert.ConditionAllOf)
            }

            foreach ($cond in $conditions) {
                # Check Field/Equals pattern (new module)
                if ($cond.Field -eq 'operationName' -and $cond.Equals -eq $targetOperation) {
                    $matchFound = $true
                    break
                }
                # Check legacy property names
                if ($cond.field -eq 'operationName' -and $cond.equals -eq $targetOperation) {
                    $matchFound = $true
                    break
                }
            }

            if ($matchFound) { break }
        }

        if ($matchFound) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "An enabled activity log alert exists for operation '$targetOperation'." `
                -TotalResources 1 `
                -PassedResources 1 `
                -FailedResources 0
        }
        else {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details "No enabled activity log alert found for operation '$targetOperation'." `
                -AffectedResources @("MissingAlert:$targetOperation") `
                -TotalResources 1 `
                -PassedResources 0 `
                -FailedResources 1
        }
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Failed to evaluate activity log alerts for '$($ControlDef.OperationName)': $($_.Exception.Message)"
    }
}

#endregion

#region 3. Invoke-NSGPortCheck

function Test-PortInRange {
    <#
    .SYNOPSIS
        Tests whether a specific port number falls within a port range string.
    .DESCRIPTION
        Accepts range strings such as "3389", "3000-4000", or "*" (all ports).
        Returns $true if the target port is within the range.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$TargetPort,

        [Parameter(Mandatory)]
        [string]$RangeString
    )

    $RangeString = $RangeString.Trim()

    # Wildcard matches everything
    if ($RangeString -eq '*') { return $true }

    # Range format: "3000-4000"
    if ($RangeString -match '^\s*(\d+)\s*-\s*(\d+)\s*$') {
        $low  = [int]$Matches[1]
        $high = [int]$Matches[2]
        return ($TargetPort -ge $low -and $TargetPort -le $high)
    }

    # Single port
    if ($RangeString -match '^\s*(\d+)\s*$') {
        return ($TargetPort -eq [int]$Matches[1])
    }

    return $false
}

function Invoke-NSGPortCheck {
    <#
    .SYNOPSIS
        Checks NSGs for inbound Allow rules that expose specified ports to the Internet.
    .DESCRIPTION
        For each NSG, inspects inbound rules that allow traffic from Internet sources
        (*, 0.0.0.0/0, 0.0.0.0, Internet, Any) for the specified port and protocol.
        Special case: Port=-1 means check ALL ports for the given protocol.
        Port can be an array (e.g., @(80,443)) for multi-port checks.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter()]
        [object[]]$CachedNSGs = @()
    )

    try {
        $targetPorts = $ControlDef.Port
        $protocol    = $ControlDef.Protocol
        $serviceName = $ControlDef.ServiceName

        # Normalize port to array
        if ($targetPorts -isnot [array]) {
            $targetPorts = @($targetPorts)
        }

        $checkAllPorts = ($targetPorts.Count -eq 1 -and $targetPorts[0] -eq -1)

        # Internet source prefixes to flag
        $internetSources = @('*', '0.0.0.0/0', '0.0.0.0', 'Internet', 'Any')

        if ($null -eq $CachedNSGs -or $CachedNSGs.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No NSGs found in the subscription. Control not evaluated." `
                -TotalResources 0 `
                -PassedResources 0 `
                -FailedResources 0
        }

        $totalNSGs    = $CachedNSGs.Count
        $failedNSGs   = 0
        $affected      = [System.Collections.Generic.List[string]]::new()

        foreach ($nsg in $CachedNSGs) {
            $nsgName   = $nsg.Name
            $nsgFailed = $false

            # Combine default and custom security rules
            $allRules = @()
            if ($nsg.SecurityRules)        { $allRules += $nsg.SecurityRules }
            if ($nsg.DefaultSecurityRules) { $allRules += $nsg.DefaultSecurityRules }

            foreach ($rule in $allRules) {
                # Only inspect inbound Allow rules
                if ($rule.Direction -ne 'Inbound') { continue }
                if ($rule.Access    -ne 'Allow')   { continue }

                # Check protocol match (TCP, UDP, or * for any)
                $ruleProtocol = $rule.Protocol
                if ($ruleProtocol -ne '*' -and $ruleProtocol -ne $protocol) { continue }

                # Check if the source is an Internet address
                $sourceMatched = $false
                $sourcePrefixes = @()

                if ($rule.SourceAddressPrefix) {
                    $sourcePrefixes += $rule.SourceAddressPrefix
                }
                if ($rule.SourceAddressPrefixes) {
                    $sourcePrefixes += $rule.SourceAddressPrefixes
                }

                foreach ($prefix in $sourcePrefixes) {
                    if ($prefix -in $internetSources) {
                        $sourceMatched = $true
                        break
                    }
                }

                if (-not $sourceMatched) { continue }

                # Check if destination port matches
                $portMatched = $false
                $destPorts   = @()

                if ($rule.DestinationPortRange) {
                    $destPorts += $rule.DestinationPortRange
                }
                if ($rule.DestinationPortRanges) {
                    $destPorts += $rule.DestinationPortRanges
                }

                if ($checkAllPorts) {
                    # Port=-1: flag any rule that allows ANY traffic for this protocol from the Internet
                    # A wildcard or any explicit range means exposure
                    if ($destPorts.Count -gt 0) {
                        $portMatched = $true
                    }
                }
                else {
                    foreach ($portRange in $destPorts) {
                        foreach ($tp in $targetPorts) {
                            if (Test-PortInRange -TargetPort $tp -RangeString $portRange) {
                                $portMatched = $true
                                break
                            }
                        }
                        if ($portMatched) { break }
                    }
                }

                if ($portMatched) {
                    $nsgFailed = $true
                    break
                }
            }

            if ($nsgFailed) {
                $failedNSGs++
                $affected.Add("NSG:$nsgName (allows $serviceName from Internet)")
            }
        }

        $passedNSGs = $totalNSGs - $failedNSGs
        $portDisplay = if ($checkAllPorts) { "all $protocol ports" } else { "port(s) $($targetPorts -join ',')" }

        if ($failedNSGs -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "None of the $totalNSGs NSGs allow inbound $serviceName ($portDisplay) from the Internet." `
                -TotalResources $totalNSGs `
                -PassedResources $passedNSGs `
                -FailedResources 0
        }
        else {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details "$failedNSGs of $totalNSGs NSGs allow inbound $serviceName ($portDisplay) from the Internet." `
                -AffectedResources $affected.ToArray() `
                -TotalResources $totalNSGs `
                -PassedResources $passedNSGs `
                -FailedResources $failedNSGs
        }
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Failed to evaluate NSG rules for $($ControlDef.ServiceName): $($_.Exception.Message)"
    }
}

#endregion

#region 4. Invoke-StorageAccountPropertyCheck

function Invoke-StorageAccountPropertyCheck {
    <#
    .SYNOPSIS
        Checks a property on each storage account against an expected value.
    .DESCRIPTION
        Supports dot-notation property paths (e.g., "NetworkRuleSet.DefaultAction") to navigate
        nested objects on the storage account resource.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter()]
        [object[]]$CachedStorageAccounts = @()
    )

    try {
        $propertyPath  = $ControlDef.PropertyPath
        $expectedValue = $ControlDef.ExpectedValue

        if ($null -eq $CachedStorageAccounts -or $CachedStorageAccounts.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No storage accounts found in the subscription. Control not evaluated." `
                -TotalResources 0 `
                -PassedResources 0 `
                -FailedResources 0
        }

        $total    = $CachedStorageAccounts.Count
        $passed   = 0
        $failed   = 0
        $affected = [System.Collections.Generic.List[string]]::new()

        foreach ($sa in $CachedStorageAccounts) {
            $saName = $sa.StorageAccountName

            # Navigate the dot-notation property path
            $currentObj = $sa
            $segments   = $propertyPath.Split('.')
            $resolved   = $true

            foreach ($segment in $segments) {
                if ($null -eq $currentObj) {
                    $resolved = $false
                    break
                }
                try {
                    $currentObj = $currentObj.$segment
                }
                catch {
                    $resolved = $false
                    break
                }
            }

            $actualValue = if ($resolved) { $currentObj } else { $null }

            # Compare: handle $null expected, boolean, and string comparisons
            $isMatch = $false
            if ($null -eq $expectedValue) {
                $isMatch = ($null -eq $actualValue)
            }
            elseif ($expectedValue -is [bool]) {
                $isMatch = ($actualValue -eq $expectedValue)
            }
            else {
                $isMatch = ([string]$actualValue -eq [string]$expectedValue)
            }

            if ($isMatch) {
                $passed++
            }
            else {
                $failed++
                $affected.Add("StorageAccount:$saName ($propertyPath='$actualValue', expected='$expectedValue')")
            }
        }

        if ($failed -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "All $total storage accounts have $propertyPath set to '$expectedValue'." `
                -TotalResources $total `
                -PassedResources $passed `
                -FailedResources 0
        }
        else {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details "$failed of $total storage accounts do not have $propertyPath set to '$expectedValue'." `
                -AffectedResources $affected.ToArray() `
                -TotalResources $total `
                -PassedResources $passed `
                -FailedResources $failed
        }
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Failed to check storage account property '$($ControlDef.PropertyPath)': $($_.Exception.Message)"
    }
}

#endregion

#region 5. Invoke-StorageBlobPropertyCheck

function Invoke-StorageBlobPropertyCheck {
    <#
    .SYNOPSIS
        Checks blob service properties for each storage account.
    .DESCRIPTION
        Supports CheckType values: BlobSoftDelete, ContainerSoftDelete, BlobVersioning.
        Uses pre-cached blob service properties when available, falls back to API calls.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter()]
        [object[]]$CachedStorageAccounts = @(),

        [Parameter()]
        [hashtable]$CachedBlobProperties = @{}
    )

    try {
        $checkType = $ControlDef.CheckType

        if ($null -eq $CachedStorageAccounts -or $CachedStorageAccounts.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No storage accounts found in the subscription. Control not evaluated." `
                -TotalResources 0 `
                -PassedResources 0 `
                -FailedResources 0
        }

        $total    = $CachedStorageAccounts.Count
        $passed   = 0
        $failed   = 0
        $affected = [System.Collections.Generic.List[string]]::new()

        foreach ($sa in $CachedStorageAccounts) {
            $saName = $sa.StorageAccountName
            $rgName = $sa.ResourceGroupName

            try {
                # Use cached properties if available, otherwise fetch
                $blobService = if ($CachedBlobProperties -and $CachedBlobProperties.ContainsKey($saName)) {
                    $CachedBlobProperties[$saName]
                } else {
                    Get-AzStorageBlobServiceProperty `
                        -StorageAccountName $saName `
                        -ResourceGroupName $rgName `
                        -ErrorAction Stop
                }

                $isCompliant = $false

                switch ($checkType) {
                    'BlobSoftDelete' {
                        $isCompliant = ($blobService.DeleteRetentionPolicy.Enabled -eq $true)
                    }
                    'ContainerSoftDelete' {
                        $isCompliant = ($blobService.ContainerDeleteRetentionPolicy.Enabled -eq $true)
                    }
                    'BlobVersioning' {
                        $isCompliant = ($blobService.IsVersioningEnabled -eq $true)
                    }
                    default {
                        $isCompliant = $false
                    }
                }

                if ($isCompliant) {
                    $passed++
                }
                else {
                    $failed++
                    $affected.Add("StorageAccount:$saName ($checkType not enabled)")
                }
            }
            catch {
                $failed++
                $affected.Add("StorageAccount:$saName (error checking $checkType - $($_.Exception.Message))")
            }
        }

        if ($failed -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "All $total storage accounts have $checkType enabled." `
                -TotalResources $total `
                -PassedResources $passed `
                -FailedResources 0
        }
        else {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details "$failed of $total storage accounts do not have $checkType enabled." `
                -AffectedResources $affected.ToArray() `
                -TotalResources $total `
                -PassedResources $passed `
                -FailedResources $failed
        }
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Failed to check blob property '$($ControlDef.CheckType)': $($_.Exception.Message)"
    }
}

#endregion

#region 6. Invoke-StorageFilePropertyCheck

function Invoke-StorageFilePropertyCheck {
    <#
    .SYNOPSIS
        Checks file service properties for each storage account.
    .DESCRIPTION
        Supports CheckType values: SoftDelete, SMBVersion, SMBEncryption.
        Uses pre-cached file service properties when available, falls back to API calls.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter()]
        [object[]]$CachedStorageAccounts = @(),

        [Parameter()]
        [hashtable]$CachedFileProperties = @{}
    )

    try {
        $checkType = $ControlDef.CheckType

        if ($null -eq $CachedStorageAccounts -or $CachedStorageAccounts.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No storage accounts found in the subscription. Control not evaluated." `
                -TotalResources 0 `
                -PassedResources 0 `
                -FailedResources 0
        }

        $total    = $CachedStorageAccounts.Count
        $passed   = 0
        $failed   = 0
        $affected = [System.Collections.Generic.List[string]]::new()

        foreach ($sa in $CachedStorageAccounts) {
            $saName = $sa.StorageAccountName
            $rgName = $sa.ResourceGroupName

            try {
                # Use cached properties if available, otherwise fetch
                $fileService = if ($CachedFileProperties -and $CachedFileProperties.ContainsKey($saName)) {
                    $CachedFileProperties[$saName]
                } else {
                    Get-AzStorageFileServiceProperty `
                        -StorageAccountName $saName `
                        -ResourceGroupName $rgName `
                        -ErrorAction Stop
                }

                $isCompliant = $false

                switch ($checkType) {
                    'SoftDelete' {
                        $isCompliant = ($fileService.ShareDeleteRetentionPolicy.Enabled -eq $true)
                    }
                    'SMBVersion' {
                        # Minimum SMB version should be 3.1.1 or higher
                        $smbSetting = $fileService.ProtocolSetting.Smb.Versions
                        if ($smbSetting) {
                            # If explicitly configured, check that only SMB3.1.1 (or higher) is allowed
                            # Versions may be a string like "SMB3.1.1" or a semicolon-separated list
                            $versions = ($smbSetting -split '[;,]') | ForEach-Object { $_.Trim() }
                            # Fail if SMB2.1 or SMB3.0 are permitted alongside or instead of 3.1.1
                            $hasLegacy = $versions | Where-Object { $_ -match 'SMB2|SMB3\.0' }
                            $isCompliant = ($null -eq $hasLegacy -or $hasLegacy.Count -eq 0)
                        }
                        else {
                            # Default: Azure allows all SMB versions including legacy
                            $isCompliant = $false
                        }
                    }
                    'SMBEncryption' {
                        # Channel encryption should include AES-256-GCM
                        $encSetting = $fileService.ProtocolSetting.Smb.ChannelEncryption
                        if ($encSetting) {
                            $isCompliant = ($encSetting -match 'AES-256-GCM')
                        }
                        else {
                            $isCompliant = $false
                        }
                    }
                    default {
                        $isCompliant = $false
                    }
                }

                if ($isCompliant) {
                    $passed++
                }
                else {
                    $failed++
                    $affected.Add("StorageAccount:$saName ($checkType not configured correctly)")
                }
            }
            catch {
                $failed++
                $affected.Add("StorageAccount:$saName (error checking $checkType - $($_.Exception.Message))")
            }
        }

        if ($failed -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "All $total storage accounts have $checkType configured correctly." `
                -TotalResources $total `
                -PassedResources $passed `
                -FailedResources 0
        }
        else {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details "$failed of $total storage accounts do not have $checkType configured correctly." `
                -AffectedResources $affected.ToArray() `
                -TotalResources $total `
                -PassedResources $passed `
                -FailedResources $failed
        }
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Failed to check file service property '$($ControlDef.CheckType)': $($_.Exception.Message)"
    }
}

#endregion

#region 7. Invoke-KeyVaultPropertyCheck

function Invoke-KeyVaultPropertyCheck {
    <#
    .SYNOPSIS
        Checks a property on each Key Vault against an expected value.
    .DESCRIPTION
        The cached Key Vault list from Get-AzKeyVault returns basic info only.
        This function retrieves full details via Get-AzKeyVault -VaultName for each vault,
        then navigates the PropertyPath and compares to ExpectedValue.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter()]
        [object[]]$CachedKeyVaults = @()
    )

    try {
        $propertyPath  = $ControlDef.PropertyPath
        $expectedValue = $ControlDef.ExpectedValue

        if ($null -eq $CachedKeyVaults -or $CachedKeyVaults.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No Key Vaults found in the subscription. Control not evaluated." `
                -TotalResources 0 `
                -PassedResources 0 `
                -FailedResources 0
        }

        $total    = $CachedKeyVaults.Count
        $passed   = 0
        $failed   = 0
        $affected = [System.Collections.Generic.List[string]]::new()

        foreach ($kv in $CachedKeyVaults) {
            $vaultName = $kv.VaultName
            $rgName    = $kv.ResourceGroupName

            try {
                # Retrieve full vault details
                $vaultDetail = Get-AzKeyVault -VaultName $vaultName -ResourceGroupName $rgName -ErrorAction Stop

                # Navigate dot-notation property path
                $currentObj = $vaultDetail
                $segments   = $propertyPath.Split('.')
                $resolved   = $true

                foreach ($segment in $segments) {
                    if ($null -eq $currentObj) {
                        $resolved = $false
                        break
                    }
                    try {
                        $currentObj = $currentObj.$segment
                    }
                    catch {
                        $resolved = $false
                        break
                    }
                }

                $actualValue = if ($resolved) { $currentObj } else { $null }

                # Compare values
                $isMatch = $false
                if ($null -eq $expectedValue) {
                    $isMatch = ($null -eq $actualValue)
                }
                elseif ($expectedValue -is [bool]) {
                    $isMatch = ($actualValue -eq $expectedValue)
                }
                else {
                    $isMatch = ([string]$actualValue -eq [string]$expectedValue)
                }

                if ($isMatch) {
                    $passed++
                }
                else {
                    $failed++
                    $affected.Add("KeyVault:$vaultName ($propertyPath='$actualValue', expected='$expectedValue')")
                }
            }
            catch {
                $failed++
                $affected.Add("KeyVault:$vaultName (error retrieving details - $($_.Exception.Message))")
            }
        }

        if ($failed -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "All $total Key Vaults have $propertyPath set to '$expectedValue'." `
                -TotalResources $total `
                -PassedResources $passed `
                -FailedResources 0
        }
        else {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details "$failed of $total Key Vaults do not have $propertyPath set to '$expectedValue'." `
                -AffectedResources $affected.ToArray() `
                -TotalResources $total `
                -PassedResources $passed `
                -FailedResources $failed
        }
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Failed to check Key Vault property '$($ControlDef.PropertyPath)': $($_.Exception.Message)"
    }
}

#endregion

#region 8. Invoke-KeyVaultKeyExpiryCheck

function Invoke-KeyVaultKeyExpiryCheck {
    <#
    .SYNOPSIS
        Checks that all keys in matching Key Vaults have an expiration date set.
    .DESCRIPTION
        Filters Key Vaults by VaultType (RBAC or NonRBAC) based on EnableRbacAuthorization,
        then retrieves keys for each vault and verifies each key has an expiration date.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter()]
        [object[]]$CachedKeyVaults = @()
    )

    try {
        $vaultType = $ControlDef.VaultType  # 'RBAC' or 'NonRBAC'

        if ($null -eq $CachedKeyVaults -or $CachedKeyVaults.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No Key Vaults found in the subscription. Control not evaluated." `
                -TotalResources 0 `
                -PassedResources 0 `
                -FailedResources 0
        }

        $totalKeys  = 0
        $passedKeys = 0
        $failedKeys = 0
        $affected   = [System.Collections.Generic.List[string]]::new()
        $vaultsChecked = 0

        foreach ($kv in $CachedKeyVaults) {
            $vaultName = $kv.VaultName
            $rgName    = $kv.ResourceGroupName

            try {
                # Get full vault details to check RBAC authorization
                $vaultDetail = Get-AzKeyVault -VaultName $vaultName -ResourceGroupName $rgName -ErrorAction Stop

                $isRBAC = ($vaultDetail.EnableRbacAuthorization -eq $true)

                # Filter by vault type
                if ($vaultType -eq 'RBAC' -and -not $isRBAC) { continue }
                if ($vaultType -eq 'NonRBAC' -and $isRBAC)   { continue }

                $vaultsChecked++

                # Get all keys in this vault
                $keys = @(Get-AzKeyVaultKey -VaultName $vaultName -ErrorAction Stop)

                foreach ($key in $keys) {
                    # Skip disabled keys
                    if ($key.Enabled -eq $false) { continue }

                    $totalKeys++

                    if ($null -ne $key.Expires) {
                        $passedKeys++
                    }
                    else {
                        $failedKeys++
                        $affected.Add("KeyVault:$vaultName/Key:$($key.Name) (no expiration date)")
                    }
                }
            }
            catch {
                # Access denied or other error on specific vault - record but continue
                $affected.Add("KeyVault:$vaultName (error listing keys - $($_.Exception.Message))")
            }
        }

        if ($vaultsChecked -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No $vaultType Key Vaults found in the subscription. Control not evaluated." `
                -TotalResources 0 `
                -PassedResources 0 `
                -FailedResources 0
        }

        if ($failedKeys -eq 0 -and $affected.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "All $totalKeys key(s) across $vaultsChecked $vaultType vault(s) have an expiration date set." `
                -TotalResources $totalKeys `
                -PassedResources $passedKeys `
                -FailedResources 0
        }
        else {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details "$failedKeys of $totalKeys key(s) across $vaultsChecked $vaultType vault(s) do not have an expiration date." `
                -AffectedResources $affected.ToArray() `
                -TotalResources $totalKeys `
                -PassedResources $passedKeys `
                -FailedResources $failedKeys
        }
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Failed to check Key Vault key expiry ($($ControlDef.VaultType)): $($_.Exception.Message)"
    }
}

#endregion

#region 9. Invoke-KeyVaultSecretExpiryCheck

function Invoke-KeyVaultSecretExpiryCheck {
    <#
    .SYNOPSIS
        Checks that all secrets in matching Key Vaults have an expiration date set.
    .DESCRIPTION
        Filters Key Vaults by VaultType (RBAC or NonRBAC) based on EnableRbacAuthorization,
        then retrieves secrets for each vault and verifies each secret has an expiration date.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter()]
        [object[]]$CachedKeyVaults = @()
    )

    try {
        $vaultType = $ControlDef.VaultType  # 'RBAC' or 'NonRBAC'

        if ($null -eq $CachedKeyVaults -or $CachedKeyVaults.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No Key Vaults found in the subscription. Control not evaluated." `
                -TotalResources 0 `
                -PassedResources 0 `
                -FailedResources 0
        }

        $totalSecrets  = 0
        $passedSecrets = 0
        $failedSecrets = 0
        $affected      = [System.Collections.Generic.List[string]]::new()
        $vaultsChecked = 0

        foreach ($kv in $CachedKeyVaults) {
            $vaultName = $kv.VaultName
            $rgName    = $kv.ResourceGroupName

            try {
                # Get full vault details to check RBAC authorization
                $vaultDetail = Get-AzKeyVault -VaultName $vaultName -ResourceGroupName $rgName -ErrorAction Stop

                $isRBAC = ($vaultDetail.EnableRbacAuthorization -eq $true)

                # Filter by vault type
                if ($vaultType -eq 'RBAC' -and -not $isRBAC) { continue }
                if ($vaultType -eq 'NonRBAC' -and $isRBAC)   { continue }

                $vaultsChecked++

                # Get all secrets in this vault
                $secrets = @(Get-AzKeyVaultSecret -VaultName $vaultName -ErrorAction Stop)

                foreach ($secret in $secrets) {
                    # Skip disabled secrets
                    if ($secret.Enabled -eq $false) { continue }

                    $totalSecrets++

                    if ($null -ne $secret.Expires) {
                        $passedSecrets++
                    }
                    else {
                        $failedSecrets++
                        $affected.Add("KeyVault:$vaultName/Secret:$($secret.Name) (no expiration date)")
                    }
                }
            }
            catch {
                # Access denied or other error on specific vault - record but continue
                $affected.Add("KeyVault:$vaultName (error listing secrets - $($_.Exception.Message))")
            }
        }

        if ($vaultsChecked -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No $vaultType Key Vaults found in the subscription. Control not evaluated." `
                -TotalResources 0 `
                -PassedResources 0 `
                -FailedResources 0
        }

        if ($failedSecrets -eq 0 -and $affected.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "All $totalSecrets secret(s) across $vaultsChecked $vaultType vault(s) have an expiration date set." `
                -TotalResources $totalSecrets `
                -PassedResources $passedSecrets `
                -FailedResources 0
        }
        else {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details "$failedSecrets of $totalSecrets secret(s) across $vaultsChecked $vaultType vault(s) do not have an expiration date." `
                -AffectedResources $affected.ToArray() `
                -TotalResources $totalSecrets `
                -PassedResources $passedSecrets `
                -FailedResources $failedSecrets
        }
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Failed to check Key Vault secret expiry ($($ControlDef.VaultType)): $($_.Exception.Message)"
    }
}

#endregion

#region 10. Invoke-DiagnosticSettingCheck

function Invoke-DiagnosticSettingCheck {
    <#
    .SYNOPSIS
        Checks diagnostic settings at subscription or resource level.
    .DESCRIPTION
        Handles subscription-level diagnostic settings (Get-AzSubscriptionDiagnosticSetting)
        and resource-level diagnostic settings (Get-AzDiagnosticSetting).
        The ControlDef may specify DiagnosticLevel ('Subscription' or 'Resource'),
        RequiredCategories (array of log category names to verify), and ResourceType.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter()]
        [hashtable]$ResourceCache = @{}
    )

    try {
        $level = if ($ControlDef.DiagnosticLevel) { $ControlDef.DiagnosticLevel } else { 'Subscription' }

        switch ($level) {
            'Subscription' {
                # Check subscription-level diagnostic settings
                $diagSettings = @(Get-AzSubscriptionDiagnosticSetting -ErrorAction Stop)

                if ($diagSettings.Count -eq 0) {
                    return New-CISCheckResult `
                        -ControlId $ControlDef.ControlId `
                        -Title $ControlDef.Title `
                        -Status 'FAIL' `
                        -Details "No diagnostic settings configured for the subscription." `
                        -AffectedResources @('Subscription:CurrentSubscription') `
                        -TotalResources 1 `
                        -PassedResources 0 `
                        -FailedResources 1
                }

                # If required categories are specified, check them
                if ($ControlDef.RequiredCategories) {
                    $requiredCategories = @($ControlDef.RequiredCategories)
                    $missingCategories  = [System.Collections.Generic.List[string]]::new()

                    foreach ($reqCat in $requiredCategories) {
                        $found = $false
                        foreach ($ds in $diagSettings) {
                            $enabledLogs = @()
                            if ($ds.Log) {
                                $enabledLogs = @($ds.Log | Where-Object { $_.Enabled -eq $true } |
                                    ForEach-Object { $_.Category })
                            }
                            if ($reqCat -in $enabledLogs) {
                                $found = $true
                                break
                            }
                        }
                        if (-not $found) {
                            $missingCategories.Add($reqCat)
                        }
                    }

                    if ($missingCategories.Count -gt 0) {
                        return New-CISCheckResult `
                            -ControlId $ControlDef.ControlId `
                            -Title $ControlDef.Title `
                            -Status 'FAIL' `
                            -Details "Subscription diagnostic settings are missing required categories: $($missingCategories -join ', ')." `
                            -AffectedResources @("MissingCategories:$($missingCategories -join ',')") `
                            -TotalResources $requiredCategories.Count `
                            -PassedResources ($requiredCategories.Count - $missingCategories.Count) `
                            -FailedResources $missingCategories.Count
                    }
                }

                return New-CISCheckResult `
                    -ControlId $ControlDef.ControlId `
                    -Title $ControlDef.Title `
                    -Status 'PASS' `
                    -Details "Subscription diagnostic settings are properly configured ($($diagSettings.Count) setting(s) found)." `
                    -TotalResources 1 `
                    -PassedResources 1 `
                    -FailedResources 0
            }

            'Resource' {
                # Check resource-level diagnostic settings for a specific resource type
                $resourceType = $ControlDef.ResourceType
                $resources    = @()

                if ($resourceType -and $ResourceCache.ContainsKey($resourceType)) {
                    $resources = @($ResourceCache[$resourceType])
                }

                if ($resources.Count -eq 0) {
                    return New-CISCheckResult `
                        -ControlId $ControlDef.ControlId `
                        -Title $ControlDef.Title `
                        -Status 'PASS' `
                        -Details "N/A - No $resourceType resources found in the subscription. Control not evaluated." `
                        -TotalResources 0 `
                        -PassedResources 0 `
                        -FailedResources 0
                }

                $total    = $resources.Count
                $passed   = 0
                $failed   = 0
                $affected = [System.Collections.Generic.List[string]]::new()

                foreach ($resource in $resources) {
                    $resourceId   = $resource.Id
                    $resourceName = if ($resource.Name) { $resource.Name } else { $resourceId }

                    try {
                        $diagSettings = @(Get-AzDiagnosticSetting -ResourceId $resourceId -ErrorAction Stop)

                        if ($diagSettings.Count -gt 0) {
                            $passed++
                        }
                        else {
                            $failed++
                            $affected.Add("$($resourceType):$resourceName (no diagnostic settings)")
                        }
                    }
                    catch {
                        $failed++
                        $affected.Add("$($resourceType):$resourceName (error - $($_.Exception.Message))")
                    }
                }

                if ($failed -eq 0) {
                    return New-CISCheckResult `
                        -ControlId $ControlDef.ControlId `
                        -Title $ControlDef.Title `
                        -Status 'PASS' `
                        -Details "All $total $resourceType resources have diagnostic settings configured." `
                        -TotalResources $total `
                        -PassedResources $passed `
                        -FailedResources 0
                }
                else {
                    return New-CISCheckResult `
                        -ControlId $ControlDef.ControlId `
                        -Title $ControlDef.Title `
                        -Status 'FAIL' `
                        -Details "$failed of $total $resourceType resources lack diagnostic settings." `
                        -AffectedResources $affected.ToArray() `
                        -TotalResources $total `
                        -PassedResources $passed `
                        -FailedResources $failed
                }
            }

            default {
                return New-CISCheckResult `
                    -ControlId $ControlDef.ControlId `
                    -Title $ControlDef.Title `
                    -Status 'ERROR' `
                    -Details "Unknown DiagnosticLevel: '$level'. Expected 'Subscription' or 'Resource'."
            }
        }
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Failed to check diagnostic settings: $($_.Exception.Message)"
    }
}

#endregion

#region 11. Invoke-GraphAPIPropertyCheck

function Invoke-GraphAPIPropertyCheck {
    <#
    .SYNOPSIS
        Checks a Microsoft Graph API property against an expected value.
    .DESCRIPTION
        Uses Invoke-MgGraphRequest to query the specified Graph endpoint,
        then navigates the PropertyPath and compares to ExpectedValue.
        Requires an active Microsoft Graph connection (Connect-MgGraph).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter()]
        [hashtable]$EnvironmentInfo = @{}
    )

    try {
        # Verify Graph connection
        if ($EnvironmentInfo.NeedsGraph -and -not $EnvironmentInfo.GraphConnected) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'ERROR' `
                -Details "Microsoft Graph is not connected. Run 'Connect-MgGraph -Scopes Policy.Read.All,Directory.Read.All' first."
        }

        $endpoint      = $ControlDef.GraphEndpoint
        $propertyPath  = $ControlDef.PropertyPath
        $expectedValue = $ControlDef.ExpectedValue

        # Build the full Graph API URL
        $graphUrl = if ($endpoint -match '^https?://') {
            $endpoint
        }
        else {
            "https://graph.microsoft.com/v1.0/$endpoint"
        }

        # Call the Graph API
        $response = Invoke-MgGraphRequest -Method GET -Uri $graphUrl -ErrorAction Stop

        if ($null -eq $response) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'ERROR' `
                -Details "Graph API returned null for endpoint '$endpoint'."
        }

        # Navigate dot-notation property path
        $currentObj = $response
        $segments   = $propertyPath.Split('.')
        $resolved   = $true

        foreach ($segment in $segments) {
            if ($null -eq $currentObj) {
                $resolved = $false
                break
            }

            # Handle both PSObject properties and hashtable keys
            if ($currentObj -is [hashtable] -or $currentObj -is [System.Collections.IDictionary]) {
                if ($currentObj.ContainsKey($segment)) {
                    $currentObj = $currentObj[$segment]
                }
                else {
                    $resolved = $false
                    break
                }
            }
            else {
                try {
                    $currentObj = $currentObj.$segment
                }
                catch {
                    $resolved = $false
                    break
                }
            }
        }

        $actualValue = if ($resolved) { $currentObj } else { $null }

        # Compare values
        $isMatch = $false
        if ($null -eq $expectedValue) {
            $isMatch = ($null -eq $actualValue)
        }
        elseif ($expectedValue -is [bool]) {
            # Graph API may return booleans as strings or actual bools
            if ($actualValue -is [bool]) {
                $isMatch = ($actualValue -eq $expectedValue)
            }
            else {
                $isMatch = ([string]$actualValue -eq [string]$expectedValue)
            }
        }
        else {
            $isMatch = ([string]$actualValue -eq [string]$expectedValue)
        }

        if ($isMatch) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "Graph API property '$propertyPath' is '$actualValue' (expected '$expectedValue') at endpoint '$endpoint'." `
                -TotalResources 1 `
                -PassedResources 1 `
                -FailedResources 0
        }
        else {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details "Graph API property '$propertyPath' is '$actualValue'; expected '$expectedValue' at endpoint '$endpoint'." `
                -AffectedResources @("GraphPolicy:$endpoint ($propertyPath)") `
                -TotalResources 1 `
                -PassedResources 0 `
                -FailedResources 1
        }
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Failed to query Graph API endpoint '$($ControlDef.GraphEndpoint)': $($_.Exception.Message)"
    }
}

#endregion

#region 12. Invoke-ManualCheck

function Invoke-ManualCheck {
    <#
    .SYNOPSIS
        Returns an INFO result for controls that require manual verification.
    .DESCRIPTION
        This is the simplest handler - it returns the ManualGuidance text from the ControlDef
        with an INFO status, indicating the check cannot be automated.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef
    )

    try {
        $guidance = if ($ControlDef.ManualGuidance) {
            $ControlDef.ManualGuidance
        }
        else {
            'This control requires manual verification. Please review the CIS Benchmark documentation for audit steps.'
        }

        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'INFO' `
            -AssessmentStatus 'Manual' `
            -Details "Manual check required. Guidance: $guidance"
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Failed to generate manual check result: $($_.Exception.Message)"
    }
}

#endregion
