# =============================================================================
# Section 5: Identity Services - Custom Check Functions
# CIS Microsoft Azure Foundations Benchmark v5.0.0
# =============================================================================
# Custom functions for Identity controls that require direct API calls beyond
# the standard GraphAPIProperty pattern. Dispatched via 'Custom' CheckPattern.
# Each function receives -ControlDef (hashtable) and -ResourceCache (hashtable).
# =============================================================================

function Test-CIS512-MFAAllUsers {
    <#
    .SYNOPSIS
        CIS 5.1.2 - Ensure that 'multifactor authentication' is 'enabled' for all users.
    .DESCRIPTION
        Uses Microsoft Graph to query the userRegistrationDetails report and check
        whether all non-guest, enabled users have MFA registered.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        # Attempt to query user registration details via Graph API
        $pageSize = if ($script:CISConfig.GraphApiPageSize) { $script:CISConfig.GraphApiPageSize } else { 999 }
        $uri = "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?`$top=$pageSize"
        $allUsers         = [System.Collections.Generic.List[object]]::new()
        $currentUri       = $uri

        # Page through all results
        do {
            try {
                $response = Invoke-MgGraphRequest -Method GET -Uri $currentUri -ErrorAction Stop
            }
            catch {
                # If Graph is unavailable, fall back to Get-MgUser approach
                return Test-CIS512-MFAAllUsers-Fallback -ControlDef $ControlDef -ErrorMessage $_.Exception.Message
            }

            if ($response.value) {
                foreach ($item in $response.value) {
                    $allUsers.Add($item)
                }
            }
            $currentUri = $response.'@odata.nextLink'
        } while ($currentUri)

        if ($allUsers.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'WARNING' `
                -Details "No user registration details returned from Graph API. Verify permissions (UserAuthenticationMethod.Read.All)." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        # Exclude guest users and disabled accounts - CIS requirement targets active organization members only
        $allUsers = @($allUsers | Where-Object {
            $_.userType -ne 'Guest' -and
            ($_.isAdmin -ne $null -or $_.userPrincipalName -ne $null)  # ensure valid user objects
        })
        # Filter out disabled accounts if the property is available
        $allUsers = @($allUsers | Where-Object {
            # userRegistrationDetails may include an isEnabled or accountEnabled property
            $enabled = $_.isEnabled
            if ($null -eq $enabled) { $enabled = $_.accountEnabled }
            # If the property is not available, include the user (assume enabled)
            $null -eq $enabled -or $enabled -eq $true
        })

        if ($allUsers.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'WARNING' `
                -Details "No non-guest users found in user registration details." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $totalCount  = $allUsers.Count
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        foreach ($user in $allUsers) {
            $isMfaRegistered = $false
            if ($user.isMfaRegistered -eq $true) {
                $isMfaRegistered = $true
            }
            elseif ($user.methodsRegistered -and ($user.methodsRegistered -match 'mfa|microsoftAuthenticator|fido2|softwareOneTimePasscode|passKeyDeviceBound|windowsHelloForBusiness')) {
                # Strong MFA methods only — SMS/phone alone is not considered strong MFA per NIST SP 800-63B
                $isMfaRegistered = $true
            }

            if ($isMfaRegistered) {
                $passedCount++
            }
            else {
                # Redact PII: show only first initial and domain to avoid leaking full names/UPNs in reports
                $upn = $user.userPrincipalName
                if ($upn -and $upn -match '^(.)[^@]*(@.+)$') {
                    $redacted = "$($Matches[1])***$($Matches[2])"
                } else {
                    $redacted = if ($user.userDisplayName) { "$($user.userDisplayName[0])***" } else { 'Unknown' }
                }
                $failedList.Add($redacted)
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            # Cap the displayed list to avoid excessively long details
            $displayMax   = if ($script:CISConfig.MaxDisplayItems) { $script:CISConfig.MaxDisplayItems } else { 20 }
            $displayNames = if ($failedCount -le $displayMax) { $failedList -join '; ' } else { ($failedList[0..($displayMax - 1)] -join '; ') + " ... and $($failedCount - $displayMax) more" }
            $details      = "$failedCount of $totalCount user(s) do not have MFA registered: $displayNames"
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
            -Details "All $totalCount user(s) have MFA registered." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking MFA status for all users: $(Format-CISErrorMessage $_.Exception.Message)"
    }
}

function Test-CIS512-MFAAllUsers-Fallback {
    <#
    .SYNOPSIS
        Fallback MFA check when Graph registration details endpoint is unavailable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter()]
        [string]$ErrorMessage
    )

    try {
        $users = @(Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AccountEnabled, UserType -ErrorAction Stop |
            Where-Object { $_.AccountEnabled -eq $true -and $_.UserType -ne 'Guest' })

        if ($users.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'WARNING' `
                -Details "No enabled users found via Get-MgUser. Original Graph error: $ErrorMessage" `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $totalCount  = $users.Count
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        $maxUsers = if ($script:CISConfig.MfaFallbackMaxUsers) { $script:CISConfig.MfaFallbackMaxUsers } else { 500 }
        if ($totalCount -gt $maxUsers) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'WARNING' `
                -Details "Tenant has $totalCount enabled users, exceeding fallback MFA check limit of $maxUsers. Use the primary Graph API endpoint (UserAuthenticationMethod.Read.All scope) for accurate results. Connect with: Connect-MgGraph -Scopes UserAuthenticationMethod.Read.All" `
                -TotalResources $totalCount -PassedResources 0 -FailedResources 0
        }

        # Strong MFA method type fragments only — per CIS v5.0.0 and NIST SP 800-63B,
        # phone/SMS and TemporaryAccessPass are not considered strong MFA methods
        $mfaMethodTypes = @(
            'Fido2', 'MicrosoftAuthenticator',
            'SoftwareOath', 'WindowsHelloForBusiness',
            'Passkey'
        )

        foreach ($user in $users) {
            try {
                $methods = @(Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction Stop)
                # Check if any registered method is MFA-capable (not just password or email)
                $hasMfaMethod = $false
                foreach ($method in $methods) {
                    $methodType = if ($method.AdditionalProperties.'@odata.type') {
                        $method.AdditionalProperties.'@odata.type'
                    } else { '' }
                    foreach ($mfaType in $mfaMethodTypes) {
                        if ($methodType -match $mfaType) {
                            $hasMfaMethod = $true
                            break
                        }
                    }
                    if ($hasMfaMethod) { break }
                }

                if ($hasMfaMethod) {
                    $passedCount++
                }
                else {
                    # Redact PII: show only first initial to avoid leaking full names in reports
                    $redactedName = if ($user.UserPrincipalName -and $user.UserPrincipalName -match '^(.)[^@]*(@.+)$') { "$($Matches[1])***$($Matches[2])" } elseif ($user.DisplayName) { "$($user.DisplayName[0])***" } else { 'Unknown' }
                    $failedList.Add($redactedName)
                }
            }
            catch {
                $redactedName = if ($user.DisplayName) { "$($user.DisplayName[0])***" } else { 'Unknown' }
                $failedList.Add("$redactedName [Error retrieving methods]")
            }

            # Throttle to avoid rate limiting
            $batchSize = if ($script:CISConfig.MfaFallbackBatchSize) { $script:CISConfig.MfaFallbackBatchSize } else { 50 }
            if (($passedCount + $failedList.Count) % $batchSize -eq 0 -and ($passedCount + $failedList.Count) -gt 0) {
                Start-Sleep -Milliseconds 500
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $displayMax   = if ($script:CISConfig.MaxDisplayItems) { $script:CISConfig.MaxDisplayItems } else { 20 }
            $displayNames = if ($failedCount -le $displayMax) { $failedList -join '; ' } else { ($failedList[0..($displayMax - 1)] -join '; ') + " ... and $($failedCount - $displayMax) more" }
            $details      = "$failedCount of $totalCount user(s) do not have MFA-capable authentication methods registered (fallback check): $displayNames"
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
            -Details "All $totalCount user(s) have MFA-capable authentication methods registered (fallback check)." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error in MFA fallback check: $($_.Exception.Message). Original error: $ErrorMessage"
    }
}

function Test-CIS516-GuestInviteRestrictions {
    <#
    .SYNOPSIS
        CIS 5.16 - Ensure 'Guest invite restrictions' is set to 'Only users assigned to specific admin roles' or 'No one'.
    .DESCRIPTION
        Retrieves the authorization policy and checks AllowInvitesFrom equals
        'adminsAndGuestInviters' or 'none'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $allowInvitesFrom = $authPolicy.AllowInvitesFrom

        $acceptableValues = @('adminsAndGuestInviters', 'none')

        if ($allowInvitesFrom -in $acceptableValues) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "Guest invite restrictions are properly configured. AllowInvitesFrom = '$allowInvitesFrom'." `
                -TotalResources 1 -PassedResources 1 -FailedResources 0
        }

        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'FAIL' `
            -Details "Guest invite restrictions are not adequately restricted. AllowInvitesFrom = '$allowInvitesFrom'. Expected: 'adminsAndGuestInviters' or 'none'." `
            -AffectedResources @("AuthorizationPolicy (AllowInvitesFrom: $allowInvitesFrom)") `
            -TotalResources 1 -PassedResources 0 -FailedResources 1
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking guest invite restrictions: $(Format-CISErrorMessage $_.Exception.Message)"
    }
}

function Test-CIS523-CustomAdminRoles {
    <#
    .SYNOPSIS
        CIS 5.23 - Ensure that no custom subscription administrator roles exist.
    .DESCRIPTION
        Retrieves custom role definitions and checks if any have Actions containing
        the wildcard '*' which grants full subscription-level permissions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $customRoles = @(Get-AzRoleDefinition -Custom -ErrorAction Stop)

        if ($customRoles.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "No custom role definitions found." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $totalCount  = $customRoles.Count
        $failedList  = [System.Collections.Generic.List[string]]::new()
        $passedCount = 0

        foreach ($role in $customRoles) {
            $hasWildcard = $false
            if ($role.Actions) {
                foreach ($action in $role.Actions) {
                    if ($action -eq '*') {
                        $hasWildcard = $true
                        break
                    }
                }
            }

            if ($hasWildcard) {
                # Only flag roles assignable at subscription or root scope
                $isSubScope = $false
                if ($role.AssignableScopes) {
                    foreach ($scope in $role.AssignableScopes) {
                        # Match subscription scope (/subscriptions/xxx) or root scope (/)
                        if ($scope -eq '/' -or $scope -match '^/subscriptions/[^/]+$') {
                            $isSubScope = $true
                            break
                        }
                    }
                }
                else {
                    # No scopes defined — assume subscription-level (conservative)
                    $isSubScope = $true
                }

                if ($isSubScope) {
                    $scopeDisplay = if ($role.AssignableScopes) { ($role.AssignableScopes -join ', ') } else { 'unknown' }
                    $failedList.Add("$($role.Name) (Id: $($role.Id), Scopes: $scopeDisplay)")
                }
                else {
                    # Wildcard action but only at resource group or lower — not a subscription admin
                    $passedCount++
                }
            }
            else {
                $passedCount++
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount custom role(s) with wildcard (*) actions: $($failedList -join '; ')"
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
            -Details "All $totalCount custom role(s) are properly scoped without wildcard actions." `
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
            -Details "$(if ($status -eq 'WARNING') { 'Insufficient permissions' } else { 'Error' }) checking custom admin roles: $(Format-CISErrorMessage $_.Exception.Message)"
    }
}

function Test-CIS527-SubscriptionOwners {
    <#
    .SYNOPSIS
        CIS 5.27 - Ensure there are between 2 and 3 subscription owners.
    .DESCRIPTION
        Retrieves Owner role assignments at the subscription scope and verifies
        the count is between 2 and 3 (inclusive).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $ownerAssignments = @(Get-AzRoleAssignment -RoleDefinitionName 'Owner' -ErrorAction Stop |
            Where-Object { $_.Scope -match '^/subscriptions/[^/]+$' })

        # CIS benchmark counts total security principals (users, groups, SPs, managed identities)
        # assigned the Owner role — NOT expanded group memberships
        $totalCount = $ownerAssignments.Count

        $ownerDetails = ($ownerAssignments | ForEach-Object {
            $type = if ($_.ObjectType -eq 'User') { 'User' } elseif ($_.ObjectType -eq 'Group') { 'Group' } else { $_.ObjectType }
            "$($_.DisplayName) [$type]"
        }) -join ', '

        if ($totalCount -ge 2 -and $totalCount -le 3) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "Subscription has $totalCount Owner role assignment(s), within the recommended range (2-3). Owners: $ownerDetails" `
                -TotalResources $totalCount `
                -PassedResources $totalCount `
                -FailedResources 0
        }

        if ($totalCount -lt 2) {
            $details = "Subscription has only $totalCount Owner role assignment(s). Minimum 2 recommended for availability. Owners: $ownerDetails"
        }
        else {
            $details = "Subscription has $totalCount Owner role assignment(s), exceeding the recommended maximum of 3. Owners: $ownerDetails"
        }

        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'FAIL' `
            -Details $details `
            -AffectedResources ($ownerAssignments | ForEach-Object { "$($_.DisplayName) ($($_.SignInName)) [$($_.ObjectType)]" }) `
            -TotalResources $totalCount `
            -PassedResources 0 `
            -FailedResources $totalCount
    }
    catch {
        $status = if ($_.Exception.Message -match 'AuthorizationFailed|does not have authorization') { 'WARNING' } else { 'ERROR' }
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status $status `
            -Details "$(if ($status -eq 'WARNING') { 'Insufficient permissions' } else { 'Error' }) checking subscription owners: $(Format-CISErrorMessage $_.Exception.Message)"
    }
}

function Test-CIS533-UserAccessAdmin {
    <#
    .SYNOPSIS
        CIS 5.3.3 - Ensure use of 'User Access Administrator' role is restricted.
    .DESCRIPTION
        Checks for User Access Administrator role assignments at root scope (/).
        These should be empty or minimal.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $rootAssignments = @(Get-AzRoleAssignment -RoleDefinitionName 'User Access Administrator' -Scope '/' -ErrorAction Stop)

        $assignmentCount = $rootAssignments.Count

        if ($assignmentCount -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "No User Access Administrator role assignments found at root scope (/)." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        # Any assignment at root scope is a concern
        $affectedResources = $rootAssignments | ForEach-Object {
            "$($_.DisplayName) ($($_.SignInName)) - Scope: $($_.Scope)"
        }

        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'FAIL' `
            -Details "Found $assignmentCount User Access Administrator assignment(s) at root scope (/). This role should be tightly restricted. Assigned to: $(($rootAssignments | ForEach-Object { $_.DisplayName }) -join ', '). Note: Some assignments may be temporary PIM/JIT activations - verify in Azure AD PIM." `
            -AffectedResources $affectedResources `
            -TotalResources $assignmentCount `
            -PassedResources 0 `
            -FailedResources $assignmentCount
    }
    catch {
        # Permission error is common when checking root scope
        if ($_.Exception.Message -match 'AuthorizationFailed|does not have authorization') {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'WARNING' `
                -Details "Insufficient permissions to check User Access Administrator assignments at root scope. Elevated access is required. Error: $($_.Exception.Message)" `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking User Access Administrator role: $(Format-CISErrorMessage $_.Exception.Message)"
    }
}
