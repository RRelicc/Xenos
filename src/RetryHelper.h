#pragma once

#include <functional>
#include <Windows.h>
#include <vector>
#include "Win11Compat.h"
#include <BlackBone/Config.h>

class RetryHelper
{
public:
    template<typename Func>
    static NTSTATUS Retry(
        Func operation,
        int maxAttempts = 3,
        DWORD delayMs = 100,
        const std::function<bool( NTSTATUS )>& shouldRetry = nullptr
        )
    {
        NTSTATUS status = STATUS_UNSUCCESSFUL;

        for (int attempt = 1; attempt <= maxAttempts; ++attempt)
        {
            status = operation();

            if (NT_SUCCESS( status ))
                return status;

            if (shouldRetry && !shouldRetry( status ))
                break;

            if (attempt < maxAttempts)
                Sleep( delayMs );
        }

        return status;
    }

    static bool IsRetryableStatus( NTSTATUS status )
    {
        return status == STATUS_ACCESS_DENIED ||
               status == STATUS_PROCESS_IS_TERMINATING ||
               status == STATUS_TIMEOUT ||
               status == STATUS_DEVICE_NOT_READY ||
               status == STATUS_UNSUCCESSFUL;
    }

    template<typename Func>
    static NTSTATUS RetryWithBackoff(
        Func operation,
        int maxAttempts = 5,
        DWORD initialDelayMs = 50,
        double backoffMultiplier = 2.0
        )
    {
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        DWORD currentDelay = initialDelayMs;

        for (int attempt = 1; attempt <= maxAttempts; ++attempt)
        {
            status = operation();

            if (NT_SUCCESS( status ))
                return status;

            if (attempt < maxAttempts)
            {
                Sleep( currentDelay );
                currentDelay = static_cast<DWORD>(currentDelay * backoffMultiplier);
            }
        }

        return status;
    }

    template<typename Func>
    static NTSTATUS RetryUntilSuccess(
        Func operation,
        DWORD timeoutMs = 5000,
        DWORD delayMs = 100
        )
    {
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        DWORD elapsed = 0;

        while (elapsed < timeoutMs)
        {
            status = operation();

            if (NT_SUCCESS( status ))
                return status;

            Sleep( delayMs );
            elapsed += delayMs;
        }

        return STATUS_TIMEOUT;
    }

    static int GetRecommendedRetries()
    {
        if (Win11Compat::IsWindows11OrGreater())
            return 5;

        if (Win11Compat::RequiresEnhancedEvasion())
            return 4;

        return 3;
    }

    static DWORD GetRecommendedDelay()
    {
        if (Win11Compat::IsWindows11OrGreater())
            return 200;

        return 100;
    }
};
