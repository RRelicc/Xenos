#pragma once

#include <Windows.h>
#include <string>
#include <unordered_map>
#include <chrono>
#include <vector>
#include <algorithm>
#include "Win11Compat.h"

class PerformanceMonitor
{
public:
    static PerformanceMonitor& Instance()
    {
        static PerformanceMonitor instance;
        return instance;
    }

    void StartTimer( const std::string& operation )
    {
        _timers[operation] = std::chrono::high_resolution_clock::now();
    }

    double StopTimer( const std::string& operation )
    {
        auto it = _timers.find( operation );
        if (it == _timers.end())
            return 0.0;

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - it->second);

        double ms = duration.count() / 1000.0;
        _results[operation] = ms;
        _timers.erase( it );

        return ms;
    }

    double GetResult( const std::string& operation ) const
    {
        auto it = _results.find( operation );
        return it != _results.end() ? it->second : 0.0;
    }

    std::string GetReport() const
    {
        std::string report = "=== Performance Report ===\n\n";

        for (const auto& entry : _results)
        {
            char buf[256];
            sprintf_s( buf, "%s: %.3f ms\n", entry.first.c_str(), entry.second );
            report += buf;
        }

        return report;
    }

    void Clear()
    {
        _timers.clear();
        _results.clear();
    }

    double GetAverageTime() const
    {
        if (_results.empty())
            return 0.0;

        double sum = 0.0;
        for (const auto& entry : _results)
            sum += entry.second;

        return sum / _results.size();
    }

    double GetTotalTime() const
    {
        double total = 0.0;
        for (const auto& entry : _results)
            total += entry.second;
        return total;
    }

    std::vector<std::pair<std::string, double>> GetSortedResults() const
    {
        std::vector<std::pair<std::string, double>> sorted;
        for (const auto& entry : _results)
            sorted.push_back( entry );

        std::sort( sorted.begin(), sorted.end(),
            []( const auto& a, const auto& b ) { return a.second > b.second; } );

        return sorted;
    }

    void RecordMemoryUsage( size_t bytes )
    {
        _memoryUsage += bytes;
    }

    size_t GetMemoryUsage() const
    {
        return _memoryUsage;
    }

    void IncrementCounter( const std::string& name )
    {
        _counters[name]++;
    }

    size_t GetCounter( const std::string& name ) const
    {
        auto it = _counters.find( name );
        return it != _counters.end() ? it->second : 0;
    }

private:
    PerformanceMonitor() : _memoryUsage( 0 ) {}
    std::unordered_map<std::string, std::chrono::high_resolution_clock::time_point> _timers;
    std::unordered_map<std::string, double> _results;
    std::unordered_map<std::string, size_t> _counters;
    size_t _memoryUsage;

    PerformanceMonitor( const PerformanceMonitor& ) = delete;
    PerformanceMonitor& operator=( const PerformanceMonitor& ) = delete;
};

class ScopedTimer
{
public:
    ScopedTimer( const std::string& operation )
        : _operation( operation )
    {
        PerformanceMonitor::Instance().StartTimer( operation );
    }

    ~ScopedTimer()
    {
        PerformanceMonitor::Instance().StopTimer( _operation );
    }

private:
    std::string _operation;
};
