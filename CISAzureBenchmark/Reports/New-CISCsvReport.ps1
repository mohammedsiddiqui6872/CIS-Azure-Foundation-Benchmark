function New-CISCsvReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter()]
        [hashtable]$Metadata = @{}
    )

    $csvData = $Results | ForEach-Object {
        [PSCustomObject]@{
            'Control ID'        = $_.ControlId
            'Title'             = $_.Title
            'Status'            = $_.Status
            'Severity'          = $_.Severity
            'Section'           = $_.Section
            'Subsection'        = $_.Subsection
            'Assessment Status' = $_.AssessmentStatus
            'Profile Level'     = $_.ProfileLevel
            'Description'       = $_.Description
            'Details'           = $_.Details
            'Remediation'       = $_.Remediation
            'Affected Resources' = ($_.AffectedResources -join '; ')
            'Total Resources'   = $_.TotalResources
            'Passed Resources'  = $_.PassedResources
            'Failed Resources'  = $_.FailedResources
            'References'        = ($_.References -join '; ')
            'CIS Controls'      = ($_.CISControls -join '; ')
            'Timestamp'         = $_.Timestamp
            'Subscription'      = if ($Metadata.SubscriptionName) { $Metadata.SubscriptionName } else { 'N/A' }
            'Subscription ID'   = if ($Metadata.SubscriptionId) { $Metadata.SubscriptionId } else { 'N/A' }
            'Tenant ID'         = if ($Metadata.TenantId) { $Metadata.TenantId } else { 'N/A' }
        }
    }

    $csvData | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Force
    Write-Verbose "CSV report written to: $OutputPath"

    return $OutputPath
}
