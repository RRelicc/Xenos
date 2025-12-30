#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include "Win11Compat.h"

class ErrorReporter
{
public:
    struct ErrorInfo
    {
        NTSTATUS status;
        std::wstring operation;
        std::wstring details;
        std::wstring timestamp;

        ErrorInfo( NTSTATUS s, const std::wstring& op, const std::wstring& det )
            : status( s ), operation( op ), details( det )
        {
            SYSTEMTIME st;
            GetLocalTime( &st );

            wchar_t buf[64];
            swprintf_s( buf, L"%02d:%02d:%02d.%03d",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds );
            timestamp = buf;
        }
    };

    static ErrorReporter& Instance()
    {
        static ErrorReporter instance;
        return instance;
    }

    void AddError( NTSTATUS status, const std::wstring& operation, const std::wstring& details = L"" )
    {
        _errors.emplace_back( status, operation, details );
    }

    std::wstring GetReport() const
    {
        std::wstringstream ss;
        ss << L"=== Injection Error Report ===\n\n";

        for (const auto& err : _errors)
        {
            ss << L"[" << err.timestamp << L"] ";
            ss << err.operation << L"\n";
            ss << L"  Status: 0x" << std::hex << std::setw( 8 ) << std::setfill( L'0' ) << err.status << L"\n";

            if (!err.details.empty())
                ss << L"  Details: " << err.details << L"\n";

            ss << L"\n";
        }

        return ss.str();
    }

    void Clear()
    {
        _errors.clear();
    }

    bool HasErrors() const
    {
        return !_errors.empty();
    }

    size_t GetErrorCount() const
    {
        return _errors.size();
    }

    std::vector<ErrorInfo> GetErrorsByStatus( NTSTATUS status ) const
    {
        std::vector<ErrorInfo> filtered;
        for (const auto& err : _errors)
        {
            if (err.status == status)
                filtered.push_back( err );
        }
        return filtered;
    }

    std::unordered_map<NTSTATUS, size_t> GetErrorStatistics() const
    {
        std::unordered_map<NTSTATUS, size_t> stats;
        for (const auto& err : _errors)
            stats[err.status]++;
        return stats;
    }

    ErrorInfo GetLastError() const
    {
        if (_errors.empty())
            return ErrorInfo( 0, L"", L"" );
        return _errors.back();
    }

    bool HasStatus( NTSTATUS status ) const
    {
        for (const auto& err : _errors)
        {
            if (err.status == status)
                return true;
        }
        return false;
    }

    void ExportToFile( const std::wstring& filename ) const
    {
        HANDLE hFile = CreateFileW( filename.c_str(), GENERIC_WRITE, 0, nullptr,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr );
        if (hFile == INVALID_HANDLE_VALUE)
            return;

        std::wstring report = GetReport();
        DWORD written = 0;
        WriteFile( hFile, report.c_str(), static_cast<DWORD>(report.size() * sizeof( wchar_t )), &written, nullptr );
        CloseHandle( hFile );
    }

private:
    ErrorReporter() = default;
    std::vector<ErrorInfo> _errors;

    ErrorReporter( const ErrorReporter& ) = delete;
    ErrorReporter& operator=( const ErrorReporter& ) = delete;
};
