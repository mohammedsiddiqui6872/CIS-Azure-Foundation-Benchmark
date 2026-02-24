# =============================================================================
# Section 8: Security Services - Custom Check Functions
# CIS Microsoft Azure Foundations Benchmark v5.0.0
# =============================================================================
# Custom functions for Defender for Cloud, Key Vault, Bastion, and DDoS
# protection controls. Dispatched via 'Custom' CheckPattern.
# Each function receives -ControlDef (hashtable) and -ResourceCache (hashtable).
# =============================================================================

function Test-CIS8133-EndpointProtection {
    <#
    .SYNOPSIS
        CIS 8.1.3.3 - Ensure 'Endpoint protection' component status is set to 'On'.
    .DESCRIPTION
        Checks if the Defender for Servers plan has the endpoint protection
        extension/sub-plan enabled.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        # Get Defender for Servers plan and check for MDE integration
        $serversPlan = Get-AzSecurityPricing -Name 'VirtualMachines' -ErrorAction Stop

        if ($serversPlan.PricingTier -ne 'Standard') {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details "Defender for Servers is not enabled (tier: $($serversPlan.PricingTier)). Endpoint protection requires Defender for Servers to be On." `
                -AffectedResources @("Defender for Servers: $($serversPlan.PricingTier)") `
                -TotalResources 1 -PassedResources 0 -FailedResources 1
        }

        # Check for MDE (Microsoft Defender for Endpoint) integration
        $hasEndpointProtection = $false
        if ($serversPlan.Extension) {
            $mdeExtension = $serversPlan.Extension | Where-Object {
                $_.Name -eq 'MdeDesignatedSubscription' -or
                $_.Name -eq 'MicrosoftDefenderForEndpoint' -or
                $_.Name -match 'endpoint'
            }
            if ($mdeExtension -and $mdeExtension.IsEnabled -ne 'False') {
                $hasEndpointProtection = $true
            }
        }

        # Alternative: Check settings via Get-AzSecuritySetting
        if (-not $hasEndpointProtection) {
            try {
                $settings = @(Get-AzSecuritySetting -ErrorAction Stop)
                $mdeSetting = $settings | Where-Object { $_.Name -eq 'WDATP' -or $_.Name -eq 'MCAS' }
                if ($mdeSetting -and $mdeSetting.Enabled -eq $true) {
                    $hasEndpointProtection = $true
                }
            }
            catch {
                Write-Verbose "Could not check security settings: $($_.Exception.Message)"
            }
        }

        if ($hasEndpointProtection) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "Endpoint protection (Microsoft Defender for Endpoint) is enabled in Defender for Servers." `
                -TotalResources 1 -PassedResources 1 -FailedResources 0
        }

        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'FAIL' `
            -Details "Endpoint protection component does not appear to be enabled in Defender for Servers. Enable MDE integration." `
            -AffectedResources @("Endpoint Protection: Not enabled") `
            -TotalResources 1 -PassedResources 0 -FailedResources 1
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking endpoint protection: $($_.Exception.Message)"
    }
}

function Test-CIS8110-VMUpdateCheck {
    <#
    .SYNOPSIS
        CIS 8.1.10 - Ensure Defender for Cloud checks VM OS for updates.
    .DESCRIPTION
        Verifies that system update assessment is enabled, either through Defender
        for Cloud recommendations or Azure Update Manager.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        # Check if Defender for Servers is enabled (required for update assessments)
        $serversPlan = Get-AzSecurityPricing -Name 'VirtualMachines' -ErrorAction Stop

        if ($serversPlan.PricingTier -ne 'Standard') {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details "Defender for Servers is not enabled (tier: $($serversPlan.PricingTier)). VM update checking requires Defender for Servers." `
                -AffectedResources @("Defender for Servers: $($serversPlan.PricingTier)") `
                -TotalResources 1 -PassedResources 0 -FailedResources 1
        }

        # Check for Azure Update Manager periodic assessment
        $hasUpdateCheck = $false

        # Check if the sub-plan or extension for vulnerability assessment exists
        if ($serversPlan.SubPlan) {
            # P1 and P2 plans include vulnerability scanning
            if ($serversPlan.SubPlan -in @('P1', 'P2')) {
                $hasUpdateCheck = $true
            }
        }

        # Additionally check for Azure Policy assignment for update assessment
        if (-not $hasUpdateCheck) {
            try {
                $policies = @(Get-AzPolicyAssignment -ErrorAction Stop |
                    Where-Object { $_.Properties.DisplayName -match 'system updates|update management|periodic assessment' })
                if ($policies.Count -gt 0) {
                    $hasUpdateCheck = $true
                }
            }
            catch {
                Write-Verbose "Could not check policy assignments: $($_.Exception.Message)"
            }
        }

        # Check for VM extensions or update assessment configuration
        if (-not $hasUpdateCheck) {
            try {
                $assessments = @(Get-AzSecurityAssessment -ErrorAction Stop |
                    Where-Object { $_.DisplayName -match 'system updates|machines should be configured' })
                if ($assessments.Count -gt 0) {
                    $hasUpdateCheck = $true
                }
            }
            catch {
                Write-Verbose "Could not check security assessments: $($_.Exception.Message)"
            }
        }

        if ($hasUpdateCheck) {
            $subPlanInfo = if ($serversPlan.SubPlan) { " (Sub-plan: $($serversPlan.SubPlan))" } else { '' }
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "Defender for Servers is enabled with VM update checking capability.$subPlanInfo" `
                -TotalResources 1 -PassedResources 1 -FailedResources 0
        }

        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'FAIL' `
            -Details "VM update checking does not appear to be properly configured." `
            -AffectedResources @("Update assessment: Not configured") `
            -TotalResources 1 -PassedResources 0 -FailedResources 1
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking VM update configuration: $($_.Exception.Message)"
    }
}

function Test-CIS8112-SecurityContactRoles {
    <#
    .SYNOPSIS
        CIS 8.1.12 - Ensure 'All users with the following roles' is set to 'Owner'.
    .DESCRIPTION
        Checks that the security contact notification settings include the Owner role.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $securityContact = Get-AzSecurityContact -ErrorAction Stop

        if (-not $securityContact) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details "No security contact configured in Defender for Cloud." `
                -AffectedResources @("Security contact: Not configured") `
                -TotalResources 1 -PassedResources 0 -FailedResources 1
        }

        # Check if Owner role is included in notification roles
        $notifyByRole = $false
        $roles = @()

        if ($securityContact.NotificationsByRole) {
            $roleState = $securityContact.NotificationsByRole.State
            $roles     = @($securityContact.NotificationsByRole.Roles)

            if ($roleState -eq 'On' -and ('Owner' -in $roles)) {
                $notifyByRole = $true
            }
        }

        if ($notifyByRole) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "Security contact is configured to notify users with the Owner role. Roles: $($roles -join ', ')" `
                -TotalResources 1 -PassedResources 1 -FailedResources 0
        }

        $currentRoles = if ($roles.Count -gt 0) { $roles -join ', ' } else { 'None configured' }
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'FAIL' `
            -Details "Security contact notifications do not include the Owner role. Current roles: $currentRoles" `
            -AffectedResources @("NotificationsByRole: $currentRoles") `
            -TotalResources 1 -PassedResources 0 -FailedResources 1
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking security contact roles: $($_.Exception.Message)"
    }
}

function Test-CIS8113-SecurityContactEmail {
    <#
    .SYNOPSIS
        CIS 8.1.13 - Ensure 'Additional email addresses' is configured with a security contact email.
    .DESCRIPTION
        Checks that at least one additional email address is configured for security
        contact notifications.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $securityContact = Get-AzSecurityContact -ErrorAction Stop

        if (-not $securityContact) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details "No security contact configured in Defender for Cloud." `
                -AffectedResources @("Security contact: Not configured") `
                -TotalResources 1 -PassedResources 0 -FailedResources 1
        }

        $emails = @()
        if ($securityContact.Email) {
            $emails = @($securityContact.Email -split ';' | Where-Object { $_.Trim() -ne '' })
        }

        if ($emails.Count -gt 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "Security contact email(s) configured: $($emails -join '; ')" `
                -TotalResources 1 -PassedResources 1 -FailedResources 0
        }

        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'FAIL' `
            -Details "No additional email addresses configured for security contact notifications." `
            -AffectedResources @("Additional email: Not configured") `
            -TotalResources 1 -PassedResources 0 -FailedResources 1
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking security contact email: $($_.Exception.Message)"
    }
}

function Test-CIS8114-AlertNotifications {
    <#
    .SYNOPSIS
        CIS 8.1.14 - Ensure 'Notify about alerts with the following severity (or higher)' is enabled.
    .DESCRIPTION
        Checks that alert notification severity is configured in security contact settings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $securityContact = Get-AzSecurityContact -ErrorAction Stop

        if (-not $securityContact) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details "No security contact configured in Defender for Cloud." `
                -AffectedResources @("Security contact: Not configured") `
                -TotalResources 1 -PassedResources 0 -FailedResources 1
        }

        $alertState        = $null
        $alertSeverity     = $null

        if ($securityContact.AlertNotifications) {
            $alertState    = $securityContact.AlertNotifications.State
            $alertSeverity = $securityContact.AlertNotifications.MinimalSeverity
        }

        if ($alertState -eq 'On' -and $alertSeverity) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "Alert notifications are enabled with minimum severity: $alertSeverity" `
                -TotalResources 1 -PassedResources 1 -FailedResources 0
        }

        $currentState = if ($alertState) { $alertState } else { 'Not configured' }
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'FAIL' `
            -Details "Alert notifications are not properly configured. State: $currentState, Severity: $(if ($alertSeverity) { $alertSeverity } else { 'Not set' })" `
            -AffectedResources @("Alert notifications: $currentState") `
            -TotalResources 1 -PassedResources 0 -FailedResources 1
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking alert notifications: $($_.Exception.Message)"
    }
}

function Test-CIS8115-AttackPathNotifications {
    <#
    .SYNOPSIS
        CIS 8.1.15 - Ensure 'Notify about attack paths with the following risk level (or higher)' is enabled.
    .DESCRIPTION
        Checks that attack path notification risk level is configured in security contact settings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $securityContact = Get-AzSecurityContact -ErrorAction Stop

        if (-not $securityContact) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details "No security contact configured in Defender for Cloud." `
                -AffectedResources @("Security contact: Not configured") `
                -TotalResources 1 -PassedResources 0 -FailedResources 1
        }

        # Check for attack path notifications in the security contact
        $hasAttackPathNotification = $false
        $riskLevel = $null

        # The NotificationsSources property may contain attack path configuration
        if ($securityContact.NotificationsSources) {
            foreach ($source in $securityContact.NotificationsSources) {
                if ($source.SourceType -eq 'AttackPath' -or $source.sourceType -eq 'AttackPath') {
                    $hasAttackPathNotification = $true
                    $riskLevel = if ($source.MinimalRiskLevel) { $source.MinimalRiskLevel } else { $source.minimalRiskLevel }
                    break
                }
            }
        }

        # Alternative: check via direct property
        if (-not $hasAttackPathNotification -and $securityContact.AttackPathNotifications) {
            if ($securityContact.AttackPathNotifications.State -eq 'On') {
                $hasAttackPathNotification = $true
                $riskLevel = $securityContact.AttackPathNotifications.MinimalRiskLevel
            }
        }

        if ($hasAttackPathNotification -and $riskLevel) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "Attack path notifications are enabled with minimum risk level: $riskLevel" `
                -TotalResources 1 -PassedResources 1 -FailedResources 0
        }

        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'FAIL' `
            -Details "Attack path notifications are not configured or risk level is not set." `
            -AffectedResources @("Attack path notifications: Not configured") `
            -TotalResources 1 -PassedResources 0 -FailedResources 1
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking attack path notifications: $($_.Exception.Message)"
    }
}

function Test-CIS838-KeyVaultPrivateEndpoints {
    <#
    .SYNOPSIS
        CIS 8.3.8 - Ensure Private Endpoints are used to access Azure Key Vault.
    .DESCRIPTION
        Checks each Key Vault for the existence of private endpoint connections.
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
                # Get full Key Vault details to check private endpoints
                $kvDetail = Get-AzKeyVault -VaultName $kv.VaultName -ResourceGroupName $kv.ResourceGroupName -ErrorAction Stop

                $peConnections = $kvDetail.NetworkAcls.VirtualNetworkResourceId
                $privateEndpoints = $kvDetail.PrivateEndpointConnections

                if ($privateEndpoints -and $privateEndpoints.Count -gt 0) {
                    $passedCount++
                }
                else {
                    $failedList.Add("$($kv.VaultName) (no private endpoints)")
                }
            }
            catch {
                # Try alternative property path from list view
                if ($kv.PrivateEndpointConnections -and $kv.PrivateEndpointConnections.Count -gt 0) {
                    $passedCount++
                }
                else {
                    $failedList.Add("$($kv.VaultName) [Error: $($_.Exception.Message)]")
                }
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount of $totalCount Key Vault(s) without private endpoints: $($failedList -join '; ')"
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
            -Details "All $totalCount Key Vault(s) have private endpoints configured." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking Key Vault private endpoints: $($_.Exception.Message)"
    }
}

function Test-CIS839-KeyRotation {
    <#
    .SYNOPSIS
        CIS 8.3.9 - Ensure automatic key rotation is enabled within Azure Key Vault.
    .DESCRIPTION
        Checks each Key Vault for keys and verifies that a rotation policy is
        configured on each key.
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

        $totalKeys   = 0
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        foreach ($kv in $keyVaults) {
            try {
                $keys = @(Get-AzKeyVaultKey -VaultName $kv.VaultName -ErrorAction Stop)

                foreach ($key in $keys) {
                    if (-not $key.Enabled) { continue }
                    $totalKeys++

                    try {
                        $rotationPolicy = Get-AzKeyVaultKeyRotationPolicy -VaultName $kv.VaultName -Name $key.Name -ErrorAction Stop

                        if ($rotationPolicy -and $rotationPolicy.LifetimeActions -and $rotationPolicy.LifetimeActions.Count -gt 0) {
                            # Check for an automatic rotate action
                            $hasRotateAction = $rotationPolicy.LifetimeActions | Where-Object {
                                $_.Action -eq 'Rotate' -or $_.Action.Type -eq 'Rotate'
                            }
                            if ($hasRotateAction) {
                                $passedCount++
                            }
                            else {
                                $failedList.Add("$($kv.VaultName)/$($key.Name) (no rotate action in policy)")
                            }
                        }
                        else {
                            $failedList.Add("$($kv.VaultName)/$($key.Name) (no rotation policy)")
                        }
                    }
                    catch {
                        $failedList.Add("$($kv.VaultName)/$($key.Name) [Error: $($_.Exception.Message)]")
                    }
                }
            }
            catch {
                Write-Verbose "Cannot access keys in $($kv.VaultName): $($_.Exception.Message)"
                $failedList.Add("$($kv.VaultName) [Access error: $($_.Exception.Message)]")
            }
        }

        if ($totalKeys -eq 0 -and $failedList.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No enabled keys found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount key(s) without automatic rotation: $($failedList -join '; ')"
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details $details `
                -AffectedResources $failedList.ToArray() `
                -TotalResources $totalKeys `
                -PassedResources $passedCount `
                -FailedResources $failedCount
        }

        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'PASS' `
            -Details "All $totalKeys key(s) across $($keyVaults.Count) Key Vault(s) have automatic rotation configured." `
            -TotalResources $totalKeys `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking key rotation policies: $($_.Exception.Message)"
    }
}

function Test-CIS8311-CertificateValidity {
    <#
    .SYNOPSIS
        CIS 8.3.11 - Ensure certificate validity period <= 12 months.
    .DESCRIPTION
        Checks certificates in Key Vaults to verify their validity period does
        not exceed 12 months (365 days).
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

        $totalCerts  = 0
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        foreach ($kv in $keyVaults) {
            try {
                $certs = @(Get-AzKeyVaultCertificate -VaultName $kv.VaultName -ErrorAction Stop)

                foreach ($cert in $certs) {
                    $totalCerts++
                    try {
                        $certDetail = Get-AzKeyVaultCertificate -VaultName $kv.VaultName -Name $cert.Name -ErrorAction Stop
                        $certPolicy = Get-AzKeyVaultCertificatePolicy -VaultName $kv.VaultName -Name $cert.Name -ErrorAction Stop

                        $validityMonths = $certPolicy.ValidityInMonths

                        if ($validityMonths -and $validityMonths -le 12) {
                            $passedCount++
                        }
                        elseif ($validityMonths) {
                            $failedList.Add("$($kv.VaultName)/$($cert.Name) (validity: $validityMonths months)")
                        }
                        else {
                            # Calculate from certificate dates
                            $notBefore = $certDetail.NotBefore
                            $expires   = $certDetail.Expires
                            if ($notBefore -and $expires) {
                                $durationDays = ($expires - $notBefore).TotalDays
                                if ($durationDays -le 366) {
                                    $passedCount++
                                }
                                else {
                                    $durationMonths = [math]::Ceiling($durationDays / 30)
                                    $failedList.Add("$($kv.VaultName)/$($cert.Name) (validity: ~$durationMonths months)")
                                }
                            }
                            else {
                                $failedList.Add("$($kv.VaultName)/$($cert.Name) (unable to determine validity period)")
                            }
                        }
                    }
                    catch {
                        $failedList.Add("$($kv.VaultName)/$($cert.Name) [Error: $($_.Exception.Message)]")
                    }
                }
            }
            catch {
                Write-Verbose "Cannot access certificates in $($kv.VaultName): $($_.Exception.Message)"
            }
        }

        if ($totalCerts -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No certificates found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount of $totalCerts certificate(s) with validity > 12 months: $($failedList -join '; ')"
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'FAIL' `
                -Details $details `
                -AffectedResources $failedList.ToArray() `
                -TotalResources $totalCerts `
                -PassedResources $passedCount `
                -FailedResources $failedCount
        }

        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'PASS' `
            -Details "All $totalCerts certificate(s) have validity period <= 12 months." `
            -TotalResources $totalCerts `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking certificate validity periods: $($_.Exception.Message)"
    }
}

function Test-CIS841-BastionHost {
    <#
    .SYNOPSIS
        CIS 8.4.1 - Ensure an Azure Bastion Host Exists.
    .DESCRIPTION
        Checks if at least one Azure Bastion host resource exists in the subscription.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $bastionHosts = @(Get-AzResource -ResourceType 'Microsoft.Network/bastionHosts' -ErrorAction Stop)

        if ($bastionHosts.Count -gt 0) {
            $names = ($bastionHosts | ForEach-Object { "$($_.Name) ($($_.Location))" }) -join ', '
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "Found $($bastionHosts.Count) Azure Bastion host(s): $names" `
                -TotalResources $bastionHosts.Count `
                -PassedResources $bastionHosts.Count `
                -FailedResources 0
        }

        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'FAIL' `
            -Details "No Azure Bastion hosts found in the subscription. Deploy a Bastion host for secure management access." `
            -AffectedResources @("No Bastion host deployed") `
            -TotalResources 0 -PassedResources 0 -FailedResources 1
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking for Bastion hosts: $($_.Exception.Message)"
    }
}

function Test-CIS85-DDoSProtection {
    <#
    .SYNOPSIS
        CIS 8.5 - Ensure Azure DDoS Network Protection is enabled on virtual networks.
    .DESCRIPTION
        Checks if a DDoS protection plan exists and is associated with VNets.
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

        # Check for DDoS protection plans
        $ddosPlans = @()
        try {
            $ddosPlans = @(Get-AzDdosProtectionPlan -ErrorAction Stop)
        }
        catch {
            Write-Verbose "Error retrieving DDoS plans: $($_.Exception.Message)"
        }

        $totalCount  = $vnets.Count
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        foreach ($vnet in $vnets) {
            $hasDDoS = $false

            if ($vnet.DdosProtectionPlan -and $vnet.DdosProtectionPlan.Id) {
                $hasDDoS = $true
            }
            elseif ($vnet.EnableDdosProtection -eq $true) {
                $hasDDoS = $true
            }

            if ($hasDDoS) {
                $passedCount++
            }
            else {
                $failedList.Add("$($vnet.Name) ($($vnet.Location))")
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $planInfo = if ($ddosPlans.Count -gt 0) {
                "DDoS plan(s) exist but are not associated with all VNets."
            } else {
                "No DDoS protection plans found in the subscription."
            }
            $details = "$failedCount of $totalCount VNet(s) without DDoS protection: $($failedList -join '; '). $planInfo"
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
            -Details "All $totalCount VNet(s) have DDoS Network Protection enabled." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking DDoS protection: $($_.Exception.Message)"
    }
}
