BeforeAll {
    # Import the module to test
    $ModulePath = Join-Path $PSScriptRoot '..' '..' 'CISAzureBenchmark' 'CISAzureBenchmark.psd1'
    if (Test-Path $ModulePath) {
        # Don't actually import (needs Az modules), but load the function
        $ModuleRoot = Join-Path $PSScriptRoot '..' '..' 'CISAzureBenchmark'
        . (Join-Path $ModuleRoot 'Public' 'Get-CISControlList.ps1')
    }
}

Describe 'Get-CISControlList' {
    It 'Function exists' {
        Get-Command Get-CISControlList -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}
