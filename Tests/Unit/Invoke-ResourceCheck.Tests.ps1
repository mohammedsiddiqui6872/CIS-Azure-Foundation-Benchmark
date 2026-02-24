BeforeAll {
    $ModuleRoot = Join-Path $PSScriptRoot '..' '..' 'CISAzureBenchmark'
    . (Join-Path $ModuleRoot 'Private' 'New-CISCheckResult.ps1')
    . (Join-Path $ModuleRoot 'Private' 'Invoke-ResourceCheck.ps1')
}

Describe 'Invoke-ResourceCheck' {
    BeforeEach {
        $controlDef = @{
            ControlId = '9.1.1'
            Title     = 'Test Resource Check'
        }
    }

    It 'Returns N/A PASS for empty resources' {
        $result = Invoke-ResourceCheck -ControlDef $controlDef -Resources @() `
            -ResourceTypeName 'storage accounts' -CheckScript { param($r) $null }
        $result.Status | Should -Be 'PASS'
        $result.Details | Should -Match 'N/A'
    }

    It 'Returns FAIL when FailOnEmpty and no resources' {
        $result = Invoke-ResourceCheck -ControlDef $controlDef -Resources @() `
            -ResourceTypeName 'Bastion hosts' -CheckScript { param($r) $null } -FailOnEmpty
        $result.Status | Should -Be 'FAIL'
    }

    It 'Returns PASS when all resources pass' {
        $resources = @(
            [PSCustomObject]@{ Name = 'res1' }
            [PSCustomObject]@{ Name = 'res2' }
        )
        $result = Invoke-ResourceCheck -ControlDef $controlDef -Resources $resources `
            -ResourceTypeName 'resources' -CheckScript { param($r) $null }
        $result.Status | Should -Be 'PASS'
        $result.PassedResources | Should -Be 2
    }

    It 'Returns FAIL when some resources fail' {
        $resources = @(
            [PSCustomObject]@{ Name = 'good'; Compliant = $true }
            [PSCustomObject]@{ Name = 'bad'; Compliant = $false }
        )
        $result = Invoke-ResourceCheck -ControlDef $controlDef -Resources $resources `
            -ResourceTypeName 'resources' -CheckScript {
                param($r)
                if (-not $r.Compliant) { "$($r.Name) is non-compliant" } else { $null }
            }
        $result.Status | Should -Be 'FAIL'
        $result.PassedResources | Should -Be 1
        $result.FailedResources | Should -Be 1
        $result.AffectedResources | Should -Contain 'bad is non-compliant'
    }
}
