function Invoke-CISCheckSafely {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache,

        [Parameter()]
        [hashtable]$EnvironmentInfo
    )

    try {
        $result = Invoke-CISControlCheck -ControlDef $ControlDef -ResourceCache $ResourceCache -EnvironmentInfo $EnvironmentInfo

        # Ensure result has required fields from definition
        # Always overlay definition metadata so controls carry correct metadata
        if ($result) {
            if (-not $result.Section)          { $result.Section = $ControlDef.Section }
            if (-not $result.Subsection)       { $result.Subsection = $ControlDef.Subsection }
            $result.Severity = $ControlDef.Severity
            # Always set from definition (defaults in New-CISCheckResult mask actual values)
            $result.ProfileLevel = $ControlDef.ProfileLevel
            $result.AssessmentStatus = $ControlDef.AssessmentStatus
            if (-not $result.Description)      { $result.Description = $ControlDef.Description }
            if (-not $result.Remediation)      { $result.Remediation = $ControlDef.Remediation }
            if (-not $result.References -or $result.References.Count -eq 0) {
                $result.References = $ControlDef.References
            }
            if (-not $result.CISControls -or $result.CISControls.Count -eq 0) {
                $result.CISControls = $ControlDef.CISControls
            }
        }

        return $result
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Severity $ControlDef.Severity `
            -Section $ControlDef.Section `
            -Subsection $ControlDef.Subsection `
            -AssessmentStatus $ControlDef.AssessmentStatus `
            -ProfileLevel $ControlDef.ProfileLevel `
            -Description $ControlDef.Description `
            -Details "Check failed with error: $(Format-CISErrorMessage -Message $_.Exception.Message)" `
            -Remediation $ControlDef.Remediation `
            -References $ControlDef.References `
            -CISControls $ControlDef.CISControls
    }
}

function Invoke-CISControlCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache,

        [Parameter()]
        [hashtable]$EnvironmentInfo
    )

    switch ($ControlDef.CheckPattern) {
        'DefenderPlan'           { Invoke-DefenderPlanCheck -ControlDef $ControlDef }
        'ActivityLogAlert'       { Invoke-ActivityLogAlertCheck -ControlDef $ControlDef -CachedAlerts $ResourceCache.ActivityLogAlerts }
        'NSGPortCheck'           { Invoke-NSGPortCheck -ControlDef $ControlDef -CachedNSGs $ResourceCache.NSGs }
        'StorageAccountProperty' { Invoke-StorageAccountPropertyCheck -ControlDef $ControlDef -CachedStorageAccounts $ResourceCache.StorageAccounts }
        'StorageBlobProperty'    { Invoke-StorageBlobPropertyCheck -ControlDef $ControlDef -CachedStorageAccounts $ResourceCache.StorageAccounts -CachedBlobProperties $ResourceCache.BlobServiceProperties }
        'StorageFileProperty'    { Invoke-StorageFilePropertyCheck -ControlDef $ControlDef -CachedStorageAccounts $ResourceCache.StorageAccounts -CachedFileProperties $ResourceCache.FileServiceProperties }
        'KeyVaultProperty'       { Invoke-KeyVaultPropertyCheck -ControlDef $ControlDef -CachedKeyVaults $ResourceCache.KeyVaults -CachedKeyVaultDetails $ResourceCache.KeyVaultDetails }
        'KeyVaultKeyExpiry'      { Invoke-KeyVaultKeyExpiryCheck -ControlDef $ControlDef -CachedKeyVaults $ResourceCache.KeyVaults -CachedKeyVaultDetails $ResourceCache.KeyVaultDetails }
        'KeyVaultSecretExpiry'   { Invoke-KeyVaultSecretExpiryCheck -ControlDef $ControlDef -CachedKeyVaults $ResourceCache.KeyVaults -CachedKeyVaultDetails $ResourceCache.KeyVaultDetails }
        'DiagnosticSetting'      { Invoke-DiagnosticSettingCheck -ControlDef $ControlDef -ResourceCache $ResourceCache }
        'GraphAPIProperty'       { Invoke-GraphAPIPropertyCheck -ControlDef $ControlDef -EnvironmentInfo $EnvironmentInfo }
        'ManualCheck'            { Invoke-ManualCheck -ControlDef $ControlDef }
        'Custom' {
            $fnName = $ControlDef.CheckFunction
            if ($fnName -and $fnName -match '^(Test-CIS|Invoke-CIS)' -and (Get-Command $fnName -ErrorAction SilentlyContinue)) {
                & $fnName -ControlDef $ControlDef -ResourceCache $ResourceCache
            }
            else {
                New-CISCheckResult `
                    -ControlId $ControlDef.ControlId `
                    -Title $ControlDef.Title `
                    -Status 'ERROR' `
                    -Details "Custom check function '$fnName' not found or does not match allowed naming convention (Test-CIS*/Invoke-CIS*)."
            }
        }
        default {
            New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'ERROR' `
                -Details "Unknown check pattern: $($ControlDef.CheckPattern)"
        }
    }
}
