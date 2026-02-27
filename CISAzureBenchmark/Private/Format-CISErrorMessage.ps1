function Format-CISErrorMessage {
    <#
    .SYNOPSIS
        Sanitizes Azure error messages for safe inclusion in reports.
    .DESCRIPTION
        Strips correlation IDs, request IDs, and excessive stack traces from
        Azure API error messages to prevent information leakage in reports.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$MaxLength = 500
    )

    $sanitized = $Message

    # Strip Azure correlation/request IDs (GUIDs in error context)
    $sanitized = $sanitized -replace 'Correlation(?:Id|RequestId)[:\s]+[a-fA-F0-9-]{36}', ''
    $sanitized = $sanitized -replace 'x-ms-request-id[:\s]+[a-fA-F0-9-]{36}', ''
    $sanitized = $sanitized -replace 'RequestId[:\s]+[a-fA-F0-9-]{36}', ''
    $sanitized = $sanitized -replace 'tracking-id[:\s]+[a-fA-F0-9-]{36}', ''

    # Strip stack traces
    $sanitized = $sanitized -replace '(?s)\s+at\s+\S+\.\S+\(.*?\)', ''

    # Trim excessive whitespace
    $sanitized = ($sanitized -replace '\s+', ' ').Trim()

    # Truncate if too long
    if ($sanitized.Length -gt $MaxLength) {
        $sanitized = $sanitized.Substring(0, $MaxLength) + '...'
    }

    return $sanitized
}
