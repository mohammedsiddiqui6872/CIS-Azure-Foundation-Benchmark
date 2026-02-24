BeforeAll {
    $ModuleRoot = Join-Path $PSScriptRoot '..' '..' 'CISAzureBenchmark'
    . (Join-Path $ModuleRoot 'Private' 'Invoke-WithRetry.ps1')
}

Describe 'Invoke-WithRetry' {
    It 'Returns result on first success' {
        $result = Invoke-WithRetry -ScriptBlock { 'success' } -MaxRetries 3
        $result | Should -Be 'success'
    }

    It 'Throws non-retryable errors immediately' {
        $script:callCount = 0
        { Invoke-WithRetry -ScriptBlock {
            $script:callCount++
            throw [System.InvalidOperationException]::new('Not retryable')
        } -MaxRetries 3 -BaseDelayMs 10 } | Should -Throw '*Not retryable*'
        $script:callCount | Should -Be 1
    }

    It 'Retries on throttling errors' {
        $script:callCount = 0
        $result = Invoke-WithRetry -ScriptBlock {
            $script:callCount++
            if ($script:callCount -lt 3) {
                throw [System.Net.Http.HttpRequestException]::new('429 Too Many Requests')
            }
            'success after retry'
        } -MaxRetries 3 -BaseDelayMs 10
        $result | Should -Be 'success after retry'
        $script:callCount | Should -Be 3
    }

    It 'Exhausts retries and throws' {
        { Invoke-WithRetry -ScriptBlock {
            throw [System.Net.Http.HttpRequestException]::new('503 Service Unavailable')
        } -MaxRetries 2 -BaseDelayMs 10 } | Should -Throw '*503*'
    }
}
