@{
    # =============================================================================
    # CIS Azure Benchmark Module Configuration
    # Override these values by passing -ConfigPath to Invoke-CISAzureBenchmark
    # =============================================================================

    # Threshold settings (days)
    RetentionThresholdDays = 90
    KeyRotationMaxDays     = 90

    # Display settings
    MaxDisplayItems        = 20

    # Retry settings
    MaxRetries             = 3
    RetryBaseDelayMs       = 1000

    # Graph API settings
    GraphApiPageSize       = 999

    # MFA fallback settings - max users before switching to WARNING
    MfaFallbackMaxUsers    = 500
    MfaFallbackBatchSize   = 50

}
