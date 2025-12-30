#pragma once

#include "Win11Compat.h"
#include "RetryHelper.h"
#include <BlackBone/Process/Process.h>
#include <string>
#include <vector>
#include <functional>

class ProcessEx
{
public:
    static NTSTATUS AttachWithRetry(
        blackbone::Process& process,
        DWORD pid,
        DWORD access = DEFAULT_ACCESS_P,
        int maxRetries = 0
        )
    {
        if (maxRetries == 0)
            maxRetries = RetryHelper::GetRecommendedRetries();

        return RetryHelper::Retry(
            [&]() { return process.Attach( pid, access ); },
            maxRetries,
            RetryHelper::GetRecommendedDelay(),
            RetryHelper::IsRetryableStatus
        );
    }

    static NTSTATUS AttachSmart( blackbone::Process& process, DWORD pid )
    {
        HANDLE hProcess = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid );
        if (!hProcess)
            return STATUS_ACCESS_DENIED;

        DWORD recommendedAccess = DEFAULT_ACCESS_P;

        if (Win11Compat::IsCFGEnabled( hProcess ))
        {
            recommendedAccess = PROCESS_VM_READ | PROCESS_VM_WRITE |
                              PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION |
                              PROCESS_CREATE_THREAD;
        }

        if (Win11Compat::IsHardenedProcess( hProcess ))
        {
            CloseHandle( hProcess );
            return process.Attach( pid, PROCESS_QUERY_LIMITED_INFORMATION );
        }

        CloseHandle( hProcess );
        return AttachWithRetry( process, pid, recommendedAccess );
    }

    static std::vector<blackbone::ProcessInfo> EnumerateProcesses( const std::wstring& nameFilter = L"" )
    {
        std::vector<blackbone::ProcessInfo> result;
        blackbone::Process::EnumByName( nameFilter, result );
        return result;
    }

    static std::vector<blackbone::ProcessInfo> EnumerateProcessesByPID( const std::vector<DWORD>& pids )
    {
        std::vector<blackbone::ProcessInfo> result;

        for (DWORD pid : pids)
        {
            blackbone::Process temp;
            if (NT_SUCCESS( temp.Attach( pid, PROCESS_QUERY_LIMITED_INFORMATION ) ))
            {
                blackbone::ProcessInfo info;
                info.pid = pid;

                wchar_t path[MAX_PATH] = { 0 };
                DWORD size = MAX_PATH;
                if (QueryFullProcessImageNameW( temp.core().handle(), 0, path, &size ))
                    info.imageName = path;

                result.push_back( info );
                temp.Detach();
            }
        }

        return result;
    }

    static bool IsProcess64Bit( blackbone::Process& process )
    {
        return !process.core().isWow64();
    }

    static bool IsProcessElevated( blackbone::Process& process )
    {
        return Win11Compat::IsProcessElevated( process.core().handle() );
    }

    static DWORD GetProcessIntegrityLevel( blackbone::Process& process )
    {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken( process.core().handle(), TOKEN_QUERY, &hToken ))
            return 0;

        DWORD dwSize = 0;
        GetTokenInformation( hToken, TokenIntegrityLevel, nullptr, 0, &dwSize );

        auto pTIL = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(malloc( dwSize ));
        if (!pTIL)
        {
            CloseHandle( hToken );
            return 0;
        }

        DWORD integrityLevel = 0;
        if (GetTokenInformation( hToken, TokenIntegrityLevel, pTIL, dwSize, &dwSize ))
        {
            DWORD sidSubAuthCount = *GetSidSubAuthorityCount( pTIL->Label.Sid );
            integrityLevel = *GetSidSubAuthority( pTIL->Label.Sid, sidSubAuthCount - 1 );
        }

        free( pTIL );
        CloseHandle( hToken );
        return integrityLevel;
    }

    static std::wstring GetProcessImagePath( blackbone::Process& process )
    {
        wchar_t path[MAX_PATH] = { 0 };
        DWORD size = MAX_PATH;

        if (QueryFullProcessImageNameW( process.core().handle(), 0, path, &size ))
            return std::wstring( path );

        return L"";
    }

    static bool SuspendProcess( blackbone::Process& process )
    {
        auto& threads = process.threads().getAll();
        bool success = true;

        for (auto& thread : threads)
        {
            if (thread->Suspend() != STATUS_SUCCESS)
                success = false;
        }

        return success;
    }

    static bool ResumeProcess( blackbone::Process& process )
    {
        auto& threads = process.threads().getAll();
        bool success = true;

        for (auto& thread : threads)
        {
            if (thread->Resume() != STATUS_SUCCESS)
                success = false;
        }

        return success;
    }

    static size_t GetProcessMemoryUsage( blackbone::Process& process )
    {
        PROCESS_MEMORY_COUNTERS_EX pmc = { 0 };
        pmc.cb = sizeof( pmc );

        if (GetProcessMemoryInfo( process.core().handle(),
                                 reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&pmc),
                                 sizeof( pmc ) ))
        {
            return pmc.WorkingSetSize;
        }

        return 0;
    }

    static bool IsProcessRunning( DWORD pid )
    {
        HANDLE hProcess = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid );
        if (!hProcess)
            return false;

        DWORD exitCode = 0;
        bool running = GetExitCodeProcess( hProcess, &exitCode ) && exitCode == STILL_ACTIVE;

        CloseHandle( hProcess );
        return running;
    }

    static NTSTATUS TerminateProcessSafe( blackbone::Process& process, DWORD exitCode = 0 )
    {
        if (Win11Compat::IsProcessElevated( process.core().handle() ))
        {
            if (!Win11Compat::IsProcessElevated())
                return STATUS_ACCESS_DENIED;
        }

        return process.Terminate( exitCode );
    }

    static std::vector<DWORD> GetChildProcesses( DWORD parentPid )
    {
        std::vector<DWORD> children;
        HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

        if (hSnapshot == INVALID_HANDLE_VALUE)
            return children;

        PROCESSENTRY32W pe = { 0 };
        pe.dwSize = sizeof( pe );

        if (Process32FirstW( hSnapshot, &pe ))
        {
            do
            {
                if (pe.th32ParentProcessID == parentPid)
                    children.push_back( pe.th32ProcessID );
            }
            while (Process32NextW( hSnapshot, &pe ));
        }

        CloseHandle( hSnapshot );
        return children;
    }

    static bool WaitForProcess( DWORD pid, DWORD timeoutMs = INFINITE )
    {
        HANDLE hProcess = OpenProcess( SYNCHRONIZE, FALSE, pid );
        if (!hProcess)
            return false;

        DWORD result = WaitForSingleObject( hProcess, timeoutMs );
        CloseHandle( hProcess );

        return result == WAIT_OBJECT_0;
    }

    static NTSTATUS CreateProcessSuspended(
        const std::wstring& path,
        const std::wstring& args,
        blackbone::Process& process
        )
    {
        STARTUPINFOW si = { 0 };
        PROCESS_INFORMATION pi = { 0 };
        si.cb = sizeof( si );

        std::wstring cmdLine = L"\"" + path + L"\" " + args;

        if (!CreateProcessW(
            path.c_str(),
            const_cast<LPWSTR>(cmdLine.c_str()),
            nullptr,
            nullptr,
            FALSE,
            CREATE_SUSPENDED,
            nullptr,
            nullptr,
            &si,
            &pi
            ))
        {
            return STATUS_UNSUCCESSFUL;
        }

        NTSTATUS status = process.Attach( pi.dwProcessId );

        if (!NT_SUCCESS( status ))
        {
            TerminateProcess( pi.hProcess, 0 );
            CloseHandle( pi.hProcess );
            CloseHandle( pi.hThread );
            return status;
        }

        CloseHandle( pi.hThread );
        return STATUS_SUCCESS;
    }
};
