function Disconnect-CISAzureBenchmark {
    <#
    .SYNOPSIS
        Disconnects from Azure and Microsoft Graph sessions.
    .DESCRIPTION
        Cleanly disconnects Azure and Microsoft Graph sessions established by Connect-CISAzureBenchmark.
    .EXAMPLE
        Disconnect-CISAzureBenchmark
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n  Disconnecting CIS Azure Benchmark sessions..." -ForegroundColor Yellow

    try {
        Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
        Write-Host "  [1/2] Azure disconnected." -ForegroundColor Green
    }
    catch {
        Write-Host "  [1/2] Azure was not connected." -ForegroundColor DarkGray
    }

    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Host "  [2/2] Microsoft Graph disconnected." -ForegroundColor Green
    }
    catch {
        Write-Host "  [2/2] Microsoft Graph was not connected." -ForegroundColor DarkGray
    }

    Write-Host "  Done." -ForegroundColor Green
    Write-Host ""
}
