function Export-CISRemediationScript {
    <#
    .SYNOPSIS
        Generates a PowerShell remediation script from CIS benchmark results.
    .DESCRIPTION
        Takes benchmark results (from Invoke-CISAzureBenchmark or a saved JSON file)
        and generates a .ps1 script with remediation guidance and commands for each
        failed control. The script includes -WhatIf support and is grouped by section.
    .PARAMETER Results
        Results object from Invoke-CISAzureBenchmark.
    .PARAMETER JsonPath
        Path to a saved JSON report file.
    .PARAMETER OutputPath
        Path for the generated remediation script. Defaults to ./CIS-Remediation.ps1.
    .EXAMPLE
        $scan = Invoke-CISAzureBenchmark -OutputDirectory ./reports
        Export-CISRemediationScript -Results $scan.Results -OutputPath ./remediate.ps1
    .EXAMPLE
        Export-CISRemediationScript -JsonPath ./reports/scan.json -OutputPath ./remediate.ps1
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName = 'FromResults')]
        [PSCustomObject[]]$Results,

        [Parameter(Mandatory, ParameterSetName = 'FromJson')]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$JsonPath,

        [Parameter()]
        [string]$OutputPath = './CIS-Remediation.ps1'
    )

    # Load results
    if ($JsonPath) {
        $json = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json
        $Results = $json.results
    }

    if (-not $Results -or $Results.Count -eq 0) {
        Write-Warning "No results provided. Use -Results or -JsonPath parameter."
        return
    }

    # Filter to FAIL results only
    $failures = @($Results | Where-Object {
        $status = if ($_.Status) { $_.Status } else { $_.status }
        $status -eq 'FAIL'
    })

    if ($failures.Count -eq 0) {
        Write-Host "  No failed controls found. No remediation script needed." -ForegroundColor Green
        return
    }

    $sb = [System.Text.StringBuilder]::new()

    [void]$sb.AppendLine('#Requires -Version 7.2')
    [void]$sb.AppendLine('#Requires -Modules Az.Accounts')
    [void]$sb.AppendLine('<#')
    [void]$sb.AppendLine('.SYNOPSIS')
    [void]$sb.AppendLine('    CIS Azure Foundations Benchmark v5.0.0 - Remediation Script')
    [void]$sb.AppendLine('.DESCRIPTION')
    [void]$sb.AppendLine("    Auto-generated remediation guidance for $($failures.Count) failed control(s).")
    [void]$sb.AppendLine("    Generated: $([DateTime]::UtcNow.ToString('o'))")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('    IMPORTANT: Review each section before executing.')
    [void]$sb.AppendLine('    Use -WhatIf where available to preview changes.')
    [void]$sb.AppendLine('#>')
    [void]$sb.AppendLine('[CmdletBinding(SupportsShouldProcess)]')
    [void]$sb.AppendLine('param()')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Write-Host "CIS Azure Benchmark v5.0.0 - Remediation Script" -ForegroundColor Cyan')
    [void]$sb.AppendLine("Write-Host `"$($failures.Count) failed control(s) to remediate`" -ForegroundColor Yellow")
    [void]$sb.AppendLine('Write-Host ""')
    [void]$sb.AppendLine('')

    # Group by section
    $grouped = $failures | Group-Object {
        $section = if ($_.Section) { $_.Section } else { $_.section }
        if ($section) { $section } else { 'Unknown' }
    } | Sort-Object Name

    foreach ($group in $grouped) {
        [void]$sb.AppendLine("# $('=' * 70)")
        [void]$sb.AppendLine("# Section: $($group.Name)")
        [void]$sb.AppendLine("# $('=' * 70)")
        [void]$sb.AppendLine('')

        foreach ($fail in $group.Group) {
            $controlId  = if ($fail.ControlId) { $fail.ControlId } else { $fail.controlId }
            $title      = if ($fail.Title) { $fail.Title } else { $fail.title }
            $details    = if ($fail.Details) { $fail.Details } else { $fail.details }
            $remediation = if ($fail.Remediation) { $fail.Remediation } else { $fail.remediation }
            $severity   = if ($fail.Severity) { $fail.Severity } else { $fail.severity }
            $affected   = if ($fail.AffectedResources) { $fail.AffectedResources } else { $fail.affectedResources }

            [void]$sb.AppendLine("# --- ${controlId}: ${title} ---")
            [void]$sb.AppendLine("# Severity: $severity")
            if ($details) {
                # Wrap details in comment
                $detailLines = $details -split "`n"
                foreach ($line in $detailLines) {
                    [void]$sb.AppendLine("# Finding: $($line.Trim())")
                }
            }
            if ($affected -and $affected.Count -gt 0) {
                [void]$sb.AppendLine("# Affected Resources:")
                $maxShow = [math]::Min($affected.Count, 10)
                for ($i = 0; $i -lt $maxShow; $i++) {
                    [void]$sb.AppendLine("#   - $($affected[$i])")
                }
                if ($affected.Count -gt 10) {
                    [void]$sb.AppendLine("#   ... and $($affected.Count - 10) more")
                }
            }
            [void]$sb.AppendLine('#')
            if ($remediation) {
                [void]$sb.AppendLine('# Remediation Steps:')
                $remLines = $remediation -split "`n"
                foreach ($line in $remLines) {
                    [void]$sb.AppendLine("#   $($line.Trim())")
                }
            }
            else {
                [void]$sb.AppendLine('# No specific remediation guidance available for this control.')
            }
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("Write-Host `"[$controlId] $title`" -ForegroundColor Yellow")
            [void]$sb.AppendLine("Write-Host `"  Status: FAIL | Severity: $severity`" -ForegroundColor Red")
            if ($remediation) {
                [void]$sb.AppendLine("Write-Host `"  See remediation steps in comments above.`" -ForegroundColor DarkGray")
            }
            [void]$sb.AppendLine('# TODO: Add specific remediation commands for your environment below')
            [void]$sb.AppendLine('# Example: Set-AzSecurityPricing -Name "VirtualMachines" -PricingTier "Standard"')
            [void]$sb.AppendLine('')
        }
    }

    [void]$sb.AppendLine("Write-Host `"`" ")
    [void]$sb.AppendLine("Write-Host `"Remediation script complete. Review and execute each section carefully.`" -ForegroundColor Cyan")

    # Write output
    $sb.ToString() | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Host "  Remediation script written to: $OutputPath" -ForegroundColor Green
    Write-Host "  Contains guidance for $($failures.Count) failed control(s)" -ForegroundColor White

    return $OutputPath
}
