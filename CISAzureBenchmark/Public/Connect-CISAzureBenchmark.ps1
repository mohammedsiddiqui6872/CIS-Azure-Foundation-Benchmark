function Connect-CISAzureBenchmark {
    <#
    .SYNOPSIS
        Connects to Azure and Microsoft Graph for CIS benchmark scanning.
    .DESCRIPTION
        Single command that establishes both Azure (Az) and Microsoft Graph connections
        with the required scopes for a full CIS benchmark scan. If already connected,
        validates existing sessions and reconnects only if needed.
    .EXAMPLE
        Connect-CISAzureBenchmark
    #>
    [CmdletBinding()]
    param()

    Write-Host ''
    Write-Host '  +============================================================+' -ForegroundColor DarkCyan
    Write-Host '  |                                                            |' -ForegroundColor DarkCyan
    Write-Host '  |' -ForegroundColor DarkCyan -NoNewline
    Write-Host '       CIS Azure Benchmark - Connection Setup             ' -ForegroundColor Cyan -NoNewline
    Write-Host '|' -ForegroundColor DarkCyan
    Write-Host '  |' -ForegroundColor DarkCyan -NoNewline
    Write-Host '                  powershellnerd.com                      ' -ForegroundColor Yellow -NoNewline
    Write-Host '|' -ForegroundColor DarkCyan
    Write-Host '  |                                                            |' -ForegroundColor DarkCyan
    Write-Host '  +============================================================+' -ForegroundColor DarkCyan
    Write-Host ''

    # --- Step 1: Connect to Azure ---
    $azContext = $null
    try {
        $azContext = Get-AzContext -ErrorAction Stop
    }
    catch {
        $azContext = $null
    }

    if (-not $azContext -or -not $azContext.Subscription) {
        Write-Host '  [1/2] Connecting to Azure...' -ForegroundColor Yellow
        try {
            Connect-AzAccount -ErrorAction Stop | Out-Null
            $azContext = Get-AzContext -ErrorAction Stop
            Write-Host '  [1/2] Azure connected.' -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to connect to Azure: $($_.Exception.Message)"
            return
        }
    }
    else {
        Write-Host '  [1/2] Azure connected.' -ForegroundColor Green
    }

    Write-Host "        Tenant: $($azContext.Tenant.Id)" -ForegroundColor DarkGray

    # --- Step 2: Connect to Microsoft Graph ---
    $graphScopes = @('Policy.Read.All', 'Directory.Read.All', 'UserAuthenticationMethod.Read.All', 'Reports.Read.All')
    $graphConnected = $false

    try {
        $graphContext = Get-MgContext -ErrorAction Stop
        if ($graphContext) {
            $currentScopes = @($graphContext.Scopes)
            $missingScopes = @($graphScopes | Where-Object { $_ -notin $currentScopes })
            if ($missingScopes.Count -eq 0) {
                $graphConnected = $true
            }
        }
    }
    catch {
        $graphConnected = $false
    }

    if (-not $graphConnected) {
        Write-Host '  [2/2] Connecting to Microsoft Graph...' -ForegroundColor Yellow
        try {
            Connect-MgGraph -Scopes $graphScopes -ErrorAction Stop -NoWelcome | Out-Null
            $graphConnected = $true
            Write-Host '  [2/2] Microsoft Graph connected.' -ForegroundColor Green
        }
        catch {
            Write-Host '  [2/2] Microsoft Graph failed. Identity checks will return ERROR.' -ForegroundColor Red
            Write-Host "        $($_.Exception.Message)" -ForegroundColor DarkGray
        }
    }
    else {
        Write-Host '  [2/2] Microsoft Graph connected.' -ForegroundColor Green
    }

    Write-Host ''
    Write-Host '  Ready. Run ' -ForegroundColor White -NoNewline
    Write-Host 'Invoke-CISAzureBenchmark' -ForegroundColor Cyan -NoNewline
    Write-Host ' to start.' -ForegroundColor White
    Write-Host ''
}
