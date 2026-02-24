BeforeAll {
    $ModuleRoot = Join-Path $PSScriptRoot '..' '..' 'CISAzureBenchmark'
    . (Join-Path $ModuleRoot 'Private' 'New-CISCheckResult.ps1')
    . (Join-Path $ModuleRoot 'Checks' 'CommonPatterns.ps1')
}

Describe 'Test-PortInRange' {
    It 'Matches wildcard' {
        Test-PortInRange -TargetPort 3389 -RangeString '*' | Should -BeTrue
    }

    It 'Matches exact port' {
        Test-PortInRange -TargetPort 22 -RangeString '22' | Should -BeTrue
    }

    It 'Does not match different port' {
        Test-PortInRange -TargetPort 22 -RangeString '80' | Should -BeFalse
    }

    It 'Matches port within range' {
        Test-PortInRange -TargetPort 3389 -RangeString '3000-4000' | Should -BeTrue
    }

    It 'Does not match port outside range' {
        Test-PortInRange -TargetPort 22 -RangeString '3000-4000' | Should -BeFalse
    }

    It 'Matches port at range boundary (low)' {
        Test-PortInRange -TargetPort 3000 -RangeString '3000-4000' | Should -BeTrue
    }

    It 'Matches port at range boundary (high)' {
        Test-PortInRange -TargetPort 4000 -RangeString '3000-4000' | Should -BeTrue
    }

    It 'Handles whitespace in range string' {
        Test-PortInRange -TargetPort 80 -RangeString ' 80 ' | Should -BeTrue
        Test-PortInRange -TargetPort 80 -RangeString ' 70 - 90 ' | Should -BeTrue
    }

    It 'Returns false for invalid range string' {
        Test-PortInRange -TargetPort 80 -RangeString 'abc' | Should -BeFalse
    }
}
