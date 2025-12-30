#pragma once

#include "Win11Compat.h"
#include "PPLBypass.h"
#include <BlackBone/Process/Process.h>

class ProcessProtection
{
public:
    enum ProtectionLevel
    {
        None = 0,
        Low,
        Medium,
        High,
        Maximum
    };

    static ProtectionLevel DetectProtectionLevel( blackbone::Process& process )
    {
        HANDLE hProcess = process.core().handle();
        int score = 0;

        if (Win11Compat::IsProcessElevated( hProcess ))
            score += 1;

        if (Win11Compat::IsCFGEnabled( hProcess ))
            score += 2;

        if (Win11Compat::IsDEPEnabled( hProcess ))
            score += 1;

        if (Win11Compat::IsASLREnabled( hProcess ))
            score += 1;

        DWORD mitigations = Win11Compat::GetProcessMitigationFlags( hProcess );
        if (mitigations != 0)
            score += 2;

        if (score == 0) return None;
        if (score <= 2) return Low;
        if (score <= 4) return Medium;
        if (score <= 6) return High;
        return Maximum;
    }

    static bool IsPPLProtected( DWORD pid )
    {
        HANDLE hProcess = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid );
        if (!hProcess)
            return false;

        PROCESS_PROTECTION_LEVEL_INFORMATION protectionInfo = { 0 };
        ULONG returnLength = 0;

        NTSTATUS status = NtQueryInformationProcess(
            hProcess,
            (PROCESSINFOCLASS)61,
            &protectionInfo,
            sizeof( protectionInfo ),
            &returnLength
        );

        CloseHandle( hProcess );

        return NT_SUCCESS( status ) && protectionInfo.ProtectionLevel != 0;
    }

    static NTSTATUS BypassProtection( DWORD pid, HANDLE& outHandle )
    {
        if (IsPPLProtected( pid ))
        {
            return PPLBypass::BypassPPLWithVBSCheck( pid, &outHandle );
        }

        outHandle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );
        return outHandle ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    }

    static bool RequiresElevation( blackbone::Process& process )
    {
        return Win11Compat::IsProcessElevated( process.core().handle() ) &&
               !Win11Compat::IsProcessElevated();
    }

    static bool CanInjectSafely( blackbone::Process& process )
    {
        if (Win11Compat::IsHVCIEnabled())
            return false;

        if (RequiresElevation( process ))
            return false;

        ProtectionLevel level = DetectProtectionLevel( process );
        return level <= High;
    }

    static DWORD GetRecommendedAccess( blackbone::Process& process )
    {
        ProtectionLevel level = DetectProtectionLevel( process );

        switch (level)
        {
        case None:
        case Low:
            return PROCESS_ALL_ACCESS;

        case Medium:
            return PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                   PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD;

        case High:
        case Maximum:
            return PROCESS_QUERY_LIMITED_INFORMATION;
        }

        return PROCESS_QUERY_LIMITED_INFORMATION;
    }

    static std::wstring GetProtectionDescription( ProtectionLevel level )
    {
        switch (level)
        {
        case None:    return L"No protection";
        case Low:     return L"Basic protection (DEP/ASLR)";
        case Medium:  return L"Medium protection (CFG enabled)";
        case High:    return L"High protection (Multiple mitigations)";
        case Maximum: return L"Maximum protection (Full hardening)";
        }

        return L"Unknown";
    }

    static bool IsProtectedProcess( DWORD pid )
    {
        HANDLE hProcess = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid );
        if (!hProcess)
            return true;

        bool protected_proc = Win11Compat::IsHardenedProcess( hProcess );
        CloseHandle( hProcess );

        return protected_proc || IsPPLProtected( pid );
    }

    static NTSTATUS GrantAccess( blackbone::Process& process, DWORD access )
    {
        HANDLE newHandle = nullptr;
        if (!DuplicateHandle(
            GetCurrentProcess(),
            process.core().handle(),
            GetCurrentProcess(),
            &newHandle,
            access,
            FALSE,
            0 ))
        {
            return STATUS_ACCESS_DENIED;
        }

        CloseHandle( process.core().handle() );
        return STATUS_SUCCESS;
    }
};
