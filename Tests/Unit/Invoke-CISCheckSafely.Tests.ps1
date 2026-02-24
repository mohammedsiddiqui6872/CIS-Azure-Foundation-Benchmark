BeforeAll {
    $ModuleRoot = Join-Path $PSScriptRoot '..' '..' 'CISAzureBenchmark'
    . (Join-Path $ModuleRoot 'Private' 'New-CISCheckResult.ps1')
    . (Join-Path $ModuleRoot 'Private' 'Invoke-CISCheckSafely.ps1')

    # Mock a manual check handler
    function Invoke-ManualCheck {
        param([hashtable]$ControlDef)
        New-CISCheckResult -ControlId $ControlDef.ControlId -Title $ControlDef.Title `
            -Status 'INFO' -Details 'Manual check guidance'
    }
}

Describe 'Invoke-CISCheckSafely' {
    BeforeEach {
        $controlDef = @{
            ControlId        = '3.1.1'
            Title            = 'Test Manual Control'
            Section          = 'Compute Services'
            Subsection       = 'Virtual Machines'
            Severity         = 'High'
            AssessmentStatus = 'Manual'
            ProfileLevel     = 2
            CheckPattern     = 'ManualCheck'
            Description      = 'Test description'
            Remediation      = 'Test remediation'
            References       = @('https://example.com')
            CISControls      = @('v8 1.1')
        }
        $cache = @{}
    }

    It 'Dispatches ManualCheck pattern correctly' {
        $result = Invoke-CISCheckSafely -ControlDef $controlDef -ResourceCache $cache
        $result | Should -Not -BeNullOrEmpty
        $result.Status | Should -Be 'INFO'
    }

    It 'Overlays definition metadata on result' {
        $result = Invoke-CISCheckSafely -ControlDef $controlDef -ResourceCache $cache
        $result.Section | Should -Be 'Compute Services'
        $result.Severity | Should -Be 'High'
        $result.ProfileLevel | Should -Be 2
        $result.AssessmentStatus | Should -Be 'Manual'
    }

    It 'Returns ERROR for unknown check patterns' {
        $controlDef.CheckPattern = 'NonExistentPattern'
        $result = Invoke-CISCheckSafely -ControlDef $controlDef -ResourceCache $cache
        $result.Status | Should -Be 'ERROR'
        $result.Details | Should -Match 'Unknown check pattern'
    }

    It 'Returns ERROR for missing custom function' {
        $controlDef.CheckPattern = 'Custom'
        $controlDef.CheckFunction = 'NonExistentFunction-12345'
        $result = Invoke-CISCheckSafely -ControlDef $controlDef -ResourceCache $cache
        $result.Status | Should -Be 'ERROR'
        $result.Details | Should -Match 'not found'
    }

    It 'Catches exceptions and returns ERROR status' {
        # Create a function that throws
        function Invoke-ThrowingCheck { throw 'Test exception' }
        $controlDef.CheckPattern = 'Custom'
        $controlDef.CheckFunction = 'Invoke-ThrowingCheck'
        $result = Invoke-CISCheckSafely -ControlDef $controlDef -ResourceCache $cache
        $result.Status | Should -Be 'ERROR'
        $result.Details | Should -Match 'Test exception'
    }
}
