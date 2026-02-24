Describe 'Compliance Score Calculation' {
    It 'Excludes INFO and WARNING from denominator' {
        $results = @(
            [PSCustomObject]@{ Status = 'PASS' }
            [PSCustomObject]@{ Status = 'PASS' }
            [PSCustomObject]@{ Status = 'FAIL' }
            [PSCustomObject]@{ Status = 'INFO' }
            [PSCustomObject]@{ Status = 'WARNING' }
        )
        $pass = ($results | Where-Object Status -eq 'PASS').Count
        $info = ($results | Where-Object Status -eq 'INFO').Count
        $warning = ($results | Where-Object Status -eq 'WARNING').Count
        $denom = $results.Count - $info - $warning
        $score = if ($denom -gt 0) { [math]::Round(($pass / $denom) * 100, 1) } else { 0 }
        # 2 pass / 3 (5 total - 1 INFO - 1 WARNING) = 66.7%
        $score | Should -Be 66.7
    }

    It 'Returns 0 when all results are INFO' {
        $results = @(
            [PSCustomObject]@{ Status = 'INFO' }
            [PSCustomObject]@{ Status = 'INFO' }
        )
        $pass = ($results | Where-Object Status -eq 'PASS').Count
        $info = ($results | Where-Object Status -eq 'INFO').Count
        $warning = ($results | Where-Object Status -eq 'WARNING').Count
        $denom = $results.Count - $info - $warning
        $score = if ($denom -gt 0) { [math]::Round(($pass / $denom) * 100, 1) } else { 0 }
        $score | Should -Be 0
    }

    It 'Returns 100 when all evaluated controls pass' {
        $results = @(
            [PSCustomObject]@{ Status = 'PASS' }
            [PSCustomObject]@{ Status = 'PASS' }
            [PSCustomObject]@{ Status = 'INFO' }
        )
        $pass = ($results | Where-Object Status -eq 'PASS').Count
        $info = ($results | Where-Object Status -eq 'INFO').Count
        $warning = ($results | Where-Object Status -eq 'WARNING').Count
        $denom = $results.Count - $info - $warning
        $score = if ($denom -gt 0) { [math]::Round(($pass / $denom) * 100, 1) } else { 0 }
        $score | Should -Be 100
    }
}
