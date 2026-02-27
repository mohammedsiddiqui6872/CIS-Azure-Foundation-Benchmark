function Connect-CISAzureBenchmark {
    <#
    .SYNOPSIS
        Connects to Azure and Microsoft Graph for CIS benchmark scanning.
    .DESCRIPTION
        Single command that establishes both Azure (Az) and Microsoft Graph connections
        with the required scopes for a full CIS benchmark scan. If already connected,
        validates existing sessions and reconnects only if needed.
    .PARAMETER ServicePrincipal
        Use service principal authentication (requires -Credential and -TenantId).

    .PARAMETER Credential
        PSCredential object containing the ApplicationId (username) and client secret (password)
        for service principal authentication.

    .PARAMETER CertificateThumbprint
        Certificate thumbprint for certificate-based service principal authentication
        (requires -TenantId and -ApplicationId).

    .PARAMETER ApplicationId
        Application (client) ID for certificate-based service principal authentication.

    .PARAMETER Identity
        Use managed identity authentication (for Azure VMs, App Service, etc.).

    .PARAMETER TenantId
        Azure AD tenant ID for service principal or certificate authentication.

    .EXAMPLE
        Connect-CISAzureBenchmark

    .EXAMPLE
        Connect-CISAzureBenchmark -Identity

    .EXAMPLE
        $cred = Get-Credential
        Connect-CISAzureBenchmark -ServicePrincipal -Credential $cred -TenantId '00000000-0000-0000-0000-000000000000'

    .EXAMPLE
        Connect-CISAzureBenchmark -CertificateThumbprint 'ABCDEF1234567890' -ApplicationId '00000000-0000-0000-0000-000000000000' -TenantId '00000000-0000-0000-0000-000000000000'
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$ServicePrincipal,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [string]$CertificateThumbprint,

        [Parameter()]
        [string]$ApplicationId,

        [Parameter()]
        [switch]$Identity,

        [Parameter()]
        [string]$TenantId
    )

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
            if ($Identity) {
                Write-Host '        Using managed identity authentication...' -ForegroundColor DarkGray
                Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
            }
            elseif ($ServicePrincipal) {
                if (-not $Credential -or -not $TenantId) {
                    Write-Error "Service principal authentication requires both -Credential and -TenantId parameters."
                    return
                }
                Write-Host '        Using service principal authentication...' -ForegroundColor DarkGray
                Connect-AzAccount -ServicePrincipal -Credential $Credential -TenantId $TenantId -ErrorAction Stop | Out-Null
            }
            elseif ($CertificateThumbprint) {
                if (-not $TenantId -or -not $ApplicationId) {
                    Write-Error "Certificate authentication requires both -TenantId and -ApplicationId parameters."
                    return
                }
                Write-Host '        Using certificate-based authentication...' -ForegroundColor DarkGray
                Connect-AzAccount -ServicePrincipal -CertificateThumbprint $CertificateThumbprint -TenantId $TenantId -ApplicationId $ApplicationId -ErrorAction Stop | Out-Null
            }
            else {
                Connect-AzAccount -ErrorAction Stop | Out-Null
            }
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

    $tenantDisplay = $azContext.Tenant.Id
    if ($tenantDisplay -and $tenantDisplay.Length -gt 12) {
        $tenantDisplay = $tenantDisplay.Substring(0, 4) + '****-****-****-' + $tenantDisplay.Substring($tenantDisplay.Length - 4)
    }
    Write-Host "        Tenant: $tenantDisplay" -ForegroundColor DarkGray

    # --- Step 2: Connect to Microsoft Graph ---
    # Note: These scopes are also defined in Initialize-CISEnvironment.ps1 — keep in sync
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
            if ($Identity) {
                Write-Host '        Using managed identity for Graph...' -ForegroundColor DarkGray
                Connect-MgGraph -Identity -ErrorAction Stop -NoWelcome | Out-Null
            }
            elseif ($CertificateThumbprint -and $ApplicationId -and $TenantId) {
                Write-Host '        Using certificate-based authentication for Graph...' -ForegroundColor DarkGray
                Connect-MgGraph -ClientId $ApplicationId -CertificateThumbprint $CertificateThumbprint -TenantId $TenantId -ErrorAction Stop -NoWelcome | Out-Null
            }
            elseif ($ServicePrincipal -and $Credential -and $TenantId) {
                Write-Host '        Using client secret for Graph...' -ForegroundColor DarkGray
                Connect-MgGraph -ClientSecretCredential $Credential -TenantId $TenantId -ErrorAction Stop -NoWelcome | Out-Null
            }
            else {
                Connect-MgGraph -Scopes $graphScopes -ErrorAction Stop -NoWelcome | Out-Null
            }
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
