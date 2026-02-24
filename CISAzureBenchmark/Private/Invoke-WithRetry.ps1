function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Executes a script block with exponential backoff retry logic.
    .DESCRIPTION
        Wraps Azure API calls to handle transient failures and throttling (HTTP 429).
        Retries up to MaxRetries times with exponential backoff between attempts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [int]$MaxRetries = 3,

        [Parameter()]
        [int]$BaseDelayMs = 1000,

        [Parameter()]
        [string]$OperationName = 'Azure API call'
    )

    $attempt = 0
    $lastError = $null

    while ($attempt -le $MaxRetries) {
        try {
            return (& $ScriptBlock)
        }
        catch {
            $lastError = $_
            $attempt++

            if ($attempt -gt $MaxRetries) {
                break
            }

            # Check if this is a retryable error (throttling, transient)
            $isRetryable = $false
            $errorMsg = $_.Exception.Message

            if ($errorMsg -match '429|throttl|too many requests|service unavailable|503|504|timeout|transient') {
                $isRetryable = $true
            }
            # Retry on generic network/HTTP errors
            if ($_.Exception.GetType().Name -match 'HttpRequestException|WebException|TaskCanceledException') {
                $isRetryable = $true
            }

            if (-not $isRetryable) {
                # Non-retryable error — throw immediately
                throw
            }

            $delayMs = $BaseDelayMs * [math]::Pow(2, ($attempt - 1))
            Write-Verbose "$OperationName failed (attempt $attempt/$MaxRetries): $errorMsg. Retrying in $($delayMs)ms..."
            Start-Sleep -Milliseconds $delayMs
        }
    }

    # All retries exhausted
    throw $lastError
}
