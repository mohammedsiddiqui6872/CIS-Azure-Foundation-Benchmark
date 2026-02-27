BeforeAll {
    $ModuleRoot = Join-Path $PSScriptRoot '..' '..' 'CISAzureBenchmark'
    $configPath = Join-Path $ModuleRoot 'Data' 'ModuleConfig.psd1'
}

Describe 'Module Configuration' {
    It 'Default config file exists' {
        Test-Path $configPath | Should -BeTrue
    }

    It 'Default config loads successfully' {
        $config = Import-PowerShellDataFile -Path $configPath
        $config | Should -Not -BeNullOrEmpty
    }

    It 'Contains all required keys' {
        $config = Import-PowerShellDataFile -Path $configPath
        $config.RetentionThresholdDays | Should -Not -BeNullOrEmpty
        $config.KeyRotationMaxDays | Should -Not -BeNullOrEmpty
        $config.MaxDisplayItems | Should -Not -BeNullOrEmpty
        $config.MaxRetries | Should -Not -BeNullOrEmpty
        $config.RetryBaseDelayMs | Should -Not -BeNullOrEmpty
        $config.GraphApiPageSize | Should -Not -BeNullOrEmpty
        $config.MfaFallbackMaxUsers | Should -Not -BeNullOrEmpty
        $config.MfaFallbackBatchSize | Should -Not -BeNullOrEmpty
    }

    It 'Has sensible default values' {
        $config = Import-PowerShellDataFile -Path $configPath
        $config.RetentionThresholdDays | Should -Be 90
        $config.KeyRotationMaxDays | Should -Be 90
        $config.MaxDisplayItems | Should -Be 20
        $config.MaxRetries | Should -Be 3
        $config.RetryBaseDelayMs | Should -Be 1000
        $config.GraphApiPageSize | Should -Be 999
        $config.MfaFallbackMaxUsers | Should -Be 500
        $config.MfaFallbackBatchSize | Should -Be 50
    }
}
