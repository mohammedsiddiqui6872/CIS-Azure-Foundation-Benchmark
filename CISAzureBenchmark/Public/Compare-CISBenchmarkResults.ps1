function Compare-CISBenchmarkResults {
    <#
    .SYNOPSIS
        Compares two CIS benchmark scan results to show compliance trends.
    .DESCRIPTION
        Takes a baseline and current JSON report, compares control statuses,
        and returns a trend analysis showing new failures, resolved issues,
        regressions, and improvements.
    .PARAMETER BaselinePath
        Path to the baseline (older) JSON report file.
    .PARAMETER CurrentPath
        Path to the current (newer) JSON report file.
    .PARAMETER OutputPath
        Optional path to write an HTML diff report.
    .EXAMPLE
        Compare-CISBenchmarkResults -BaselinePath ./reports/baseline.json -CurrentPath ./reports/current.json
    .EXAMPLE
        Compare-CISBenchmarkResults -BaselinePath ./baseline.json -CurrentPath ./current.json -OutputPath ./diff.html
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$BaselinePath,

        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$CurrentPath,

        [Parameter()]
        [string]$OutputPath
    )

    # Load reports
    $baseline = Get-Content -Path $BaselinePath -Raw | ConvertFrom-Json
    $current  = Get-Content -Path $CurrentPath  -Raw | ConvertFrom-Json

    $baseResults = @{}
    foreach ($r in $baseline.results) {
        $baseResults[$r.controlId] = $r
    }

    $currResults = @{}
    foreach ($r in $current.results) {
        $currResults[$r.controlId] = $r
    }

    # Categorize changes
    $newFailures  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $resolved     = [System.Collections.Generic.List[PSCustomObject]]::new()
    $regressions  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $improvements = [System.Collections.Generic.List[PSCustomObject]]::new()
    $unchanged    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $newControls  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $removedControls = [System.Collections.Generic.List[PSCustomObject]]::new()

    $statusRank = @{ 'PASS' = 4; 'INFO' = 3; 'WARNING' = 2; 'ERROR' = 1; 'FAIL' = 0 }

    foreach ($controlId in $currResults.Keys) {
        $curr = $currResults[$controlId]
        if (-not $baseResults.ContainsKey($controlId)) {
            $newControls.Add([PSCustomObject]@{
                ControlId    = $controlId
                Title        = $curr.title
                CurrentStatus = $curr.status
                Category     = 'New Control'
            })
            continue
        }

        $base = $baseResults[$controlId]
        $baseRank = if ($null -ne $statusRank[$base.status]) { $statusRank[$base.status] } else { 0 }
        $currRank = if ($null -ne $statusRank[$curr.status]) { $statusRank[$curr.status] } else { 0 }

        $change = [PSCustomObject]@{
            ControlId      = $controlId
            Title          = $curr.title
            BaselineStatus = $base.status
            CurrentStatus  = $curr.status
            Section        = $curr.section
            Severity       = $curr.severity
        }

        if ($base.status -eq $curr.status) {
            $unchanged.Add($change)
        }
        elseif ($base.status -ne 'FAIL' -and $curr.status -eq 'FAIL') {
            $newFailures.Add($change)
        }
        elseif ($base.status -eq 'FAIL' -and $curr.status -eq 'PASS') {
            $resolved.Add($change)
        }
        elseif ($currRank -lt $baseRank) {
            $regressions.Add($change)
        }
        elseif ($currRank -gt $baseRank) {
            $improvements.Add($change)
        }
        else {
            $unchanged.Add($change)
        }
    }

    # Check for removed controls
    foreach ($controlId in $baseResults.Keys) {
        if (-not $currResults.ContainsKey($controlId)) {
            $base = $baseResults[$controlId]
            $removedControls.Add([PSCustomObject]@{
                ControlId      = $controlId
                Title          = $base.title
                BaselineStatus = $base.status
                Category       = 'Removed'
            })
        }
    }

    # Calculate scores
    $baseScore = $baseline.summary.overallScore
    $currScore = $current.summary.overallScore
    $scoreDelta = if ($baseScore -ge 0 -and $currScore -ge 0) { $currScore - $baseScore } else { $null }

    $result = [PSCustomObject]@{
        PSTypeName       = 'CISBenchmarkComparison'
        BaselineScan     = $baseline.scanTimestamp
        CurrentScan      = $current.scanTimestamp
        BaselineScore    = $baseScore
        CurrentScore     = $currScore
        ScoreDelta       = $scoreDelta
        NewFailures      = $newFailures.ToArray()
        Resolved         = $resolved.ToArray()
        Regressions      = $regressions.ToArray()
        Improvements     = $improvements.ToArray()
        Unchanged        = $unchanged.ToArray()
        NewControls      = $newControls.ToArray()
        RemovedControls  = $removedControls.ToArray()
        Summary          = [PSCustomObject]@{
            NewFailureCount   = $newFailures.Count
            ResolvedCount     = $resolved.Count
            RegressionCount   = $regressions.Count
            ImprovementCount  = $improvements.Count
            UnchangedCount    = $unchanged.Count
            NewControlCount   = $newControls.Count
            RemovedCount      = $removedControls.Count
        }
    }

    # Console summary
    $trend = if ($scoreDelta -gt 0) { "improved +$scoreDelta%" } elseif ($scoreDelta -lt 0) { "declined $scoreDelta%" } elseif ($null -eq $scoreDelta) { 'N/A' } else { 'unchanged' }
    Write-Host ""
    Write-Host "  CIS Benchmark Trend Analysis" -ForegroundColor Cyan
    Write-Host "  Baseline: $($baseline.scanTimestamp) | Current: $($current.scanTimestamp)" -ForegroundColor DarkGray
    Write-Host "  Score: $baseScore% -> $currScore% ($trend)" -ForegroundColor $(if ($scoreDelta -gt 0) { 'Green' } elseif ($scoreDelta -lt 0) { 'Red' } else { 'Yellow' })
    Write-Host "  New Failures: $($newFailures.Count) | Resolved: $($resolved.Count) | Regressions: $($regressions.Count) | Improvements: $($improvements.Count)" -ForegroundColor White
    Write-Host ""

    # Generate HTML diff report if requested
    if ($OutputPath) {
        $htmlLines = [System.Text.StringBuilder]::new()
        [void]$htmlLines.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8"><title>CIS Benchmark Trend Report</title>')
        [void]$htmlLines.AppendLine('<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:1200px;margin:0 auto;padding:20px;background:#1a1a2e;color:#e0e0e0}')
        [void]$htmlLines.AppendLine('h1{color:#00d4ff}h2{color:#ccc;border-bottom:1px solid #333;padding-bottom:8px}')
        [void]$htmlLines.AppendLine('table{width:100%;border-collapse:collapse;margin:16px 0}th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #333}')
        [void]$htmlLines.AppendLine('th{background:#16213e;color:#00d4ff}.pass{color:#00c853}.fail{color:#ff5252}.warn{color:#ffd740}.info{color:#448aff}.error{color:#999}')
        [void]$htmlLines.AppendLine('.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin:20px 0}')
        [void]$htmlLines.AppendLine('.summary-card{background:#16213e;border-radius:8px;padding:20px;text-align:center}.summary-card .number{font-size:2em;font-weight:bold}')
        [void]$htmlLines.AppendLine('.delta-pos{color:#00c853}.delta-neg{color:#ff5252}.delta-zero{color:#ffd740}</style></head><body>')
        [void]$htmlLines.AppendLine("<h1>CIS Azure Benchmark - Trend Report</h1>")
        [void]$htmlLines.AppendLine("<p>Baseline: <strong>$($baseline.scanTimestamp)</strong> | Current: <strong>$($current.scanTimestamp)</strong></p>")

        $deltaClass = if ($scoreDelta -gt 0) { 'delta-pos' } elseif ($scoreDelta -lt 0) { 'delta-neg' } else { 'delta-zero' }
        $deltaStr = if ($scoreDelta -gt 0) { "+$scoreDelta%" } elseif ($null -eq $scoreDelta) { 'N/A' } else { "$scoreDelta%" }
        [void]$htmlLines.AppendLine('<div class="summary-grid">')
        [void]$htmlLines.AppendLine("<div class='summary-card'><div class='number'>$baseScore%</div><div>Baseline Score</div></div>")
        [void]$htmlLines.AppendLine("<div class='summary-card'><div class='number'>$currScore%</div><div>Current Score</div></div>")
        [void]$htmlLines.AppendLine("<div class='summary-card'><div class='number $deltaClass'>$deltaStr</div><div>Change</div></div>")
        [void]$htmlLines.AppendLine('</div>')

        [void]$htmlLines.AppendLine('<div class="summary-grid">')
        [void]$htmlLines.AppendLine("<div class='summary-card'><div class='number fail'>$($newFailures.Count)</div><div>New Failures</div></div>")
        [void]$htmlLines.AppendLine("<div class='summary-card'><div class='number pass'>$($resolved.Count)</div><div>Resolved</div></div>")
        [void]$htmlLines.AppendLine("<div class='summary-card'><div class='number warn'>$($regressions.Count)</div><div>Regressions</div></div>")
        [void]$htmlLines.AppendLine("<div class='summary-card'><div class='number info'>$($improvements.Count)</div><div>Improvements</div></div>")
        [void]$htmlLines.AppendLine('</div>')

        # Table helper
        $tableBuilder = {
            param($title, $items, $showBaseline)
            if ($items.Count -eq 0) { return }
            [void]$htmlLines.AppendLine("<h2>$title ($($items.Count))</h2><table><tr><th>Control</th><th>Title</th>")
            if ($showBaseline) { [void]$htmlLines.AppendLine('<th>Baseline</th><th>Current</th>') }
            else { [void]$htmlLines.AppendLine('<th>Status</th>') }
            [void]$htmlLines.AppendLine('</tr>')
            foreach ($item in $items) {
                $currClass = switch ($item.CurrentStatus) { 'PASS' { 'pass' } 'FAIL' { 'fail' } 'WARNING' { 'warn' } 'INFO' { 'info' } default { 'error' } }
                [void]$htmlLines.AppendLine("<tr><td>$([System.Web.HttpUtility]::HtmlEncode($item.ControlId))</td><td>$([System.Web.HttpUtility]::HtmlEncode($item.Title))</td>")
                if ($showBaseline) {
                    $baseClass = switch ($item.BaselineStatus) { 'PASS' { 'pass' } 'FAIL' { 'fail' } 'WARNING' { 'warn' } 'INFO' { 'info' } default { 'error' } }
                    [void]$htmlLines.AppendLine("<td class='$baseClass'>$($item.BaselineStatus)</td><td class='$currClass'>$($item.CurrentStatus)</td>")
                } else {
                    [void]$htmlLines.AppendLine("<td class='$currClass'>$($item.CurrentStatus)</td>")
                }
                [void]$htmlLines.AppendLine('</tr>')
            }
            [void]$htmlLines.AppendLine('</table>')
        }

        & $tableBuilder 'New Failures' $newFailures $true
        & $tableBuilder 'Resolved' $resolved $true
        & $tableBuilder 'Regressions' $regressions $true
        & $tableBuilder 'Improvements' $improvements $true

        [void]$htmlLines.AppendLine('<p style="color:#666;margin-top:40px;font-size:0.85em">Generated by CIS Azure Benchmark Module</p>')
        [void]$htmlLines.AppendLine('</body></html>')

        $htmlLines.ToString() | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        Write-Host "  Trend report written to: $OutputPath" -ForegroundColor Green
    }

    return $result
}
