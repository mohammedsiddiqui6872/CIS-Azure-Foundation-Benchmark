# =============================================================================
# Section 2: Analytics Services - Custom Check Functions
# CIS Microsoft Azure Foundations Benchmark v5.0.0
# =============================================================================
# Custom functions for Azure Databricks controls that are dispatched via the
# data-driven 'Custom' CheckPattern in Invoke-CISControlCheck.
# Each function receives -ControlDef (hashtable) and -ResourceCache (hashtable).
# =============================================================================

function Test-CIS211-DatabricksVNet {
    <#
    .SYNOPSIS
        CIS 2.1.1 - Ensure Azure Databricks is deployed in a customer-managed VNet.
    .DESCRIPTION
        Checks each Databricks workspace for VNet injection by verifying that
        CustomVirtualNetworkId is not null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $workspaces = @($ResourceCache.DatabricksWorkspaces)
        if ($workspaces.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No Azure Databricks workspaces found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $totalCount   = $workspaces.Count
        $failedList   = [System.Collections.Generic.List[string]]::new()
        $passedCount  = 0

        foreach ($ws in $workspaces) {
            $vnetId = $ws.CustomVirtualNetworkId
            if ([string]::IsNullOrWhiteSpace($vnetId)) {
                $failedList.Add("$($ws.Name) (RG: $($ws.ResourceGroupName))")
            }
            else {
                $passedCount++
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount of $totalCount Databricks workspace(s) without VNet injection: $($failedList -join '; ')"
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
            -Details "All $totalCount Databricks workspace(s) are deployed with VNet injection." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking Databricks VNet injection: $($_.Exception.Message)"
    }
}

function Test-CIS212-DatabricksNSG {
    <#
    .SYNOPSIS
        CIS 2.1.2 - Ensure NSGs are configured for Databricks subnets.
    .DESCRIPTION
        For each Databricks workspace with VNet injection, verifies that the
        associated subnets have NSGs attached.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $workspaces = @($ResourceCache.DatabricksWorkspaces)
        if ($workspaces.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No Azure Databricks workspaces found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $vnets          = @($ResourceCache.VirtualNetworks)
        $totalCount     = 0
        $failedList     = [System.Collections.Generic.List[string]]::new()
        $passedCount    = 0

        foreach ($ws in $workspaces) {
            $vnetId = $ws.CustomVirtualNetworkId
            if ([string]::IsNullOrWhiteSpace($vnetId)) { continue }

            # Find the VNet object from cache
            $vnet = $vnets | Where-Object { $_.Id -eq $vnetId } | Select-Object -First 1
            if (-not $vnet) { continue }

            # Check public and private subnets referenced by Databricks
            $subnetNames = @()
            if ($ws.CustomPublicSubnetName)  { $subnetNames += $ws.CustomPublicSubnetName }
            if ($ws.CustomPrivateSubnetName) { $subnetNames += $ws.CustomPrivateSubnetName }

            foreach ($subnetName in $subnetNames) {
                $totalCount++
                $subnet = $vnet.Subnets | Where-Object { $_.Name -eq $subnetName } | Select-Object -First 1
                if ($subnet -and $subnet.NetworkSecurityGroup) {
                    $passedCount++
                }
                else {
                    $failedList.Add("$($ws.Name)/$subnetName (VNet: $($vnet.Name))")
                }
            }
        }

        if ($totalCount -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No Databricks subnets found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount of $totalCount Databricks subnet(s) without NSGs: $($failedList -join '; ')"
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
            -Details "All $totalCount Databricks subnet(s) have NSGs configured." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking Databricks subnet NSGs: $($_.Exception.Message)"
    }
}

function Test-CIS217-DatabricksDiagnostics {
    <#
    .SYNOPSIS
        CIS 2.1.7 - Ensure diagnostic log delivery is configured for Azure Databricks.
    .DESCRIPTION
        Checks that each Databricks workspace has at least one diagnostic setting
        configured via Get-AzDiagnosticSetting.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $workspaces = @($ResourceCache.DatabricksWorkspaces)
        if ($workspaces.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No Azure Databricks workspaces found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $totalCount   = $workspaces.Count
        $failedList   = [System.Collections.Generic.List[string]]::new()
        $passedCount  = 0

        foreach ($ws in $workspaces) {
            try {
                $diagSettings = @(Get-AzDiagnosticSetting -ResourceId $ws.Id -ErrorAction Stop)
                if ($diagSettings.Count -gt 0) {
                    $passedCount++
                }
                else {
                    $failedList.Add("$($ws.Name) (RG: $($ws.ResourceGroupName))")
                }
            }
            catch {
                $failedList.Add("$($ws.Name) (RG: $($ws.ResourceGroupName)) [Error: $($_.Exception.Message)]")
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount of $totalCount Databricks workspace(s) without diagnostic settings: $($failedList -join '; ')"
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
            -Details "All $totalCount Databricks workspace(s) have diagnostic settings configured." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking Databricks diagnostic settings: $($_.Exception.Message)"
    }
}

function Test-CIS219-DatabricksNoPublicIP {
    <#
    .SYNOPSIS
        CIS 2.1.9 - Ensure 'No Public IP' is set to 'Enabled'.
    .DESCRIPTION
        Checks each Databricks workspace for the EnableNoPublicIp parameter being true,
        which prevents cluster nodes from having public IP addresses.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $workspaces = @($ResourceCache.DatabricksWorkspaces)
        if ($workspaces.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No Azure Databricks workspaces found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $totalCount   = $workspaces.Count
        $failedList   = [System.Collections.Generic.List[string]]::new()
        $passedCount  = 0

        foreach ($ws in $workspaces) {
            # EnableNoPublicIp is a workspace-level parameter in the custom parameters
            $noPublicIp = $false
            if ($ws.Parameters -and $ws.Parameters.EnableNoPublicIp) {
                $noPublicIp = $ws.Parameters.EnableNoPublicIp.Value
            }
            elseif ($ws.EnableNoPublicIp -eq $true) {
                $noPublicIp = $true
            }

            if ($noPublicIp -eq $true) {
                $passedCount++
            }
            else {
                $failedList.Add("$($ws.Name) (RG: $($ws.ResourceGroupName))")
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount of $totalCount Databricks workspace(s) without No Public IP enabled: $($failedList -join '; ')"
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
            -Details "All $totalCount Databricks workspace(s) have No Public IP enabled." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking Databricks No Public IP setting: $($_.Exception.Message)"
    }
}

function Test-CIS2110-DatabricksPublicAccess {
    <#
    .SYNOPSIS
        CIS 2.1.10 - Ensure 'Allow Public Network Access' is set to 'Disabled'.
    .DESCRIPTION
        Checks each Databricks workspace to verify PublicNetworkAccess is 'Disabled'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $workspaces = @($ResourceCache.DatabricksWorkspaces)
        if ($workspaces.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No Azure Databricks workspaces found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $totalCount   = $workspaces.Count
        $failedList   = [System.Collections.Generic.List[string]]::new()
        $passedCount  = 0

        foreach ($ws in $workspaces) {
            if ($ws.PublicNetworkAccess -eq 'Disabled') {
                $passedCount++
            }
            else {
                $currentValue = if ($ws.PublicNetworkAccess) { $ws.PublicNetworkAccess } else { 'Enabled (default)' }
                $failedList.Add("$($ws.Name) (PublicNetworkAccess: $currentValue)")
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount of $totalCount Databricks workspace(s) with public network access enabled: $($failedList -join '; ')"
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
            -Details "All $totalCount Databricks workspace(s) have public network access disabled." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking Databricks public network access: $($_.Exception.Message)"
    }
}

function Test-CIS2111-DatabricksPrivateEndpoints {
    <#
    .SYNOPSIS
        CIS 2.1.11 - Ensure private endpoints are used to access Azure Databricks workspaces.
    .DESCRIPTION
        Checks each Databricks workspace for the existence of PrivateEndpointConnections.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ControlDef,

        [Parameter(Mandatory)]
        [hashtable]$ResourceCache
    )

    try {
        $workspaces = @($ResourceCache.DatabricksWorkspaces)
        if ($workspaces.Count -eq 0) {
            return New-CISCheckResult `
                -ControlId $ControlDef.ControlId `
                -Title $ControlDef.Title `
                -Status 'PASS' `
                -Details "N/A - No Azure Databricks workspaces found in the subscription. Control not evaluated." `
                -TotalResources 0 -PassedResources 0 -FailedResources 0
        }

        $totalCount   = $workspaces.Count
        $failedList   = [System.Collections.Generic.List[string]]::new()
        $passedCount  = 0

        foreach ($ws in $workspaces) {
            $peConnections = $ws.PrivateEndpointConnections
            if ($peConnections -and $peConnections.Count -gt 0) {
                $passedCount++
            }
            else {
                $failedList.Add("$($ws.Name) (RG: $($ws.ResourceGroupName))")
            }
        }

        $failedCount = $failedList.Count
        if ($failedCount -gt 0) {
            $details = "Found $failedCount of $totalCount Databricks workspace(s) without private endpoints: $($failedList -join '; ')"
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
            -Details "All $totalCount Databricks workspace(s) have private endpoints configured." `
            -TotalResources $totalCount `
            -PassedResources $passedCount `
            -FailedResources 0
    }
    catch {
        return New-CISCheckResult `
            -ControlId $ControlDef.ControlId `
            -Title $ControlDef.Title `
            -Status 'ERROR' `
            -Details "Error checking Databricks private endpoints: $($_.Exception.Message)"
    }
}
