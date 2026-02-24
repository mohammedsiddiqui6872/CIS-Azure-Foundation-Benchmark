BeforeAll {
    $ModuleRoot = Join-Path $PSScriptRoot '..' '..' 'CISAzureBenchmark'
    . (Join-Path $ModuleRoot 'Private' 'New-CISCheckResult.ps1')
}

Describe 'New-CISCheckResult' {
    It 'Creates a result with required parameters' {
        $result = New-CISCheckResult -ControlId '7.1' -Title 'Test Control' -Status 'PASS'
        $result | Should -Not -BeNullOrEmpty
        $result.ControlId | Should -Be '7.1'
        $result.Title | Should -Be 'Test Control'
        $result.Status | Should -Be 'PASS'
        $result.PSObject.TypeNames | Should -Contain 'CISBenchmarkResult'
    }

    It 'Sets correct defaults' {
        $result = New-CISCheckResult -ControlId '1.1' -Title 'Test' -Status 'FAIL'
        $result.Severity | Should -Be 'Medium'
        $result.AssessmentStatus | Should -Be 'Automated'
        $result.ProfileLevel | Should -Be 1
        $result.AffectedResources | Should -HaveCount 0
        $result.TotalResources | Should -Be 0
    }

    It 'Rejects invalid status values' {
        { New-CISCheckResult -ControlId '1.1' -Title 'Test' -Status 'INVALID' } | Should -Throw
    }

    It 'Accepts all valid status values' {
        foreach ($status in @('PASS', 'FAIL', 'WARNING', 'INFO', 'ERROR')) {
            $result = New-CISCheckResult -ControlId '1.1' -Title 'Test' -Status $status
            $result.Status | Should -Be $status
        }
    }

    It 'Rejects invalid severity values' {
        { New-CISCheckResult -ControlId '1.1' -Title 'Test' -Status 'PASS' -Severity 'INVALID' } | Should -Throw
    }

    It 'Sets timestamp in ISO 8601 format' {
        $result = New-CISCheckResult -ControlId '1.1' -Title 'Test' -Status 'PASS'
        $result.Timestamp | Should -Match '^\d{4}-\d{2}-\d{2}T'
    }

    It 'Accepts resource counts' {
        $result = New-CISCheckResult -ControlId '1.1' -Title 'Test' -Status 'FAIL' `
            -TotalResources 10 -PassedResources 7 -FailedResources 3 `
            -AffectedResources @('res1', 'res2', 'res3')
        $result.TotalResources | Should -Be 10
        $result.PassedResources | Should -Be 7
        $result.FailedResources | Should -Be 3
        $result.AffectedResources | Should -HaveCount 3
    }
}
