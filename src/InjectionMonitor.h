#pragma once

#include "Win11Compat.h"
#include "PerformanceMonitor.h"
#include "ErrorReporter.h"
#include <string>
#include <vector>
#include <chrono>

class InjectionMonitor
{
public:
    struct InjectionResult
    {
        DWORD pid = 0;
        std::wstring imagePath;
        std::wstring processName;
        NTSTATUS status = 0;
        double durationMs = 0;
        size_t imageSize = 0;
        bool success = false;
        std::wstring errorMsg;
        std::chrono::system_clock::time_point timestamp;
    };

    struct Statistics
    {
        size_t totalAttempts = 0;
        size_t successCount = 0;
        size_t failureCount = 0;
        double averageDuration = 0;
        double totalDuration = 0;
        size_t totalBytesInjected = 0;
    };

    static void RecordInjection( const InjectionResult& result )
    {
        _history.push_back( result );

        if (_history.size() > _maxHistory)
            _history.erase( _history.begin() );

        UpdateStatistics();
    }

    static void RecordSuccess(
        DWORD pid,
        const std::wstring& imagePath,
        const std::wstring& processName,
        double durationMs,
        size_t imageSize
        )
    {
        InjectionResult result;
        result.pid = pid;
        result.imagePath = imagePath;
        result.processName = processName;
        result.status = STATUS_SUCCESS;
        result.durationMs = durationMs;
        result.imageSize = imageSize;
        result.success = true;
        result.timestamp = std::chrono::system_clock::now();

        RecordInjection( result );
    }

    static void RecordFailure(
        DWORD pid,
        const std::wstring& imagePath,
        const std::wstring& processName,
        NTSTATUS status,
        const std::wstring& errorMsg,
        double durationMs
        )
    {
        InjectionResult result;
        result.pid = pid;
        result.imagePath = imagePath;
        result.processName = processName;
        result.status = status;
        result.durationMs = durationMs;
        result.success = false;
        result.errorMsg = errorMsg;
        result.timestamp = std::chrono::system_clock::now();

        RecordInjection( result );
        ErrorReporter::Instance().ReportError( status, errorMsg );
    }

    static Statistics GetStatistics()
    {
        return _stats;
    }

    static std::vector<InjectionResult> GetHistory( size_t count = 0 )
    {
        if (count == 0 || count > _history.size())
            return _history;

        return std::vector<InjectionResult>(
            _history.end() - count,
            _history.end()
        );
    }

    static std::vector<InjectionResult> GetSuccessful()
    {
        std::vector<InjectionResult> successful;

        for (const auto& result : _history)
        {
            if (result.success)
                successful.push_back( result );
        }

        return successful;
    }

    static std::vector<InjectionResult> GetFailed()
    {
        std::vector<InjectionResult> failed;

        for (const auto& result : _history)
        {
            if (!result.success)
                failed.push_back( result );
        }

        return failed;
    }

    static InjectionResult GetLastInjection()
    {
        if (_history.empty())
            return InjectionResult();

        return _history.back();
    }

    static void ClearHistory()
    {
        _history.clear();
        _stats = Statistics();
    }

    static void SetMaxHistory( size_t max )
    {
        _maxHistory = max;

        while (_history.size() > _maxHistory)
            _history.erase( _history.begin() );
    }

    static double GetSuccessRate()
    {
        if (_stats.totalAttempts == 0)
            return 0.0;

        return (static_cast<double>(_stats.successCount) / _stats.totalAttempts) * 100.0;
    }

    static std::vector<InjectionResult> GetInjectionsByPID( DWORD pid )
    {
        std::vector<InjectionResult> results;

        for (const auto& result : _history)
        {
            if (result.pid == pid)
                results.push_back( result );
        }

        return results;
    }

    static std::vector<InjectionResult> GetInjectionsByImage( const std::wstring& imagePath )
    {
        std::vector<InjectionResult> results;

        for (const auto& result : _history)
        {
            if (result.imagePath == imagePath)
                results.push_back( result );
        }

        return results;
    }

private:
    static void UpdateStatistics()
    {
        _stats.totalAttempts = _history.size();
        _stats.successCount = 0;
        _stats.failureCount = 0;
        _stats.totalDuration = 0;
        _stats.totalBytesInjected = 0;

        for (const auto& result : _history)
        {
            if (result.success)
            {
                _stats.successCount++;
                _stats.totalBytesInjected += result.imageSize;
            }
            else
            {
                _stats.failureCount++;
            }

            _stats.totalDuration += result.durationMs;
        }

        if (_stats.totalAttempts > 0)
            _stats.averageDuration = _stats.totalDuration / _stats.totalAttempts;
    }

    static std::vector<InjectionResult> _history;
    static Statistics _stats;
    static size_t _maxHistory;
};

std::vector<InjectionMonitor::InjectionResult> InjectionMonitor::_history;
InjectionMonitor::Statistics InjectionMonitor::_stats;
size_t InjectionMonitor::_maxHistory = 100;
