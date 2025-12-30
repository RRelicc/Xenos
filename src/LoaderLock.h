#pragma once

#include <Windows.h>
#include <BlackBone/Process/Process.h>

class LoaderLock
{
public:
    static NTSTATUS AcquireLoaderLock( blackbone::Process& process, DWORD timeoutMs = 5000 )
    {
        auto ntdll = process.modules().GetModule( L"ntdll.dll" );
        if (!ntdll)
            return STATUS_DLL_NOT_FOUND;

        auto ldrLockResult = process.modules().GetExport( ntdll, "LdrLockLoaderLock" );
        if (!ldrLockResult.success())
            return STATUS_PROCEDURE_NOT_FOUND;

        auto ldrLockProc = ldrLockResult.result();

        DWORD result = process.remote().ExecDirect( ldrLockProc.procAddress, 0 );

        return STATUS_SUCCESS;
    }

    static NTSTATUS ReleaseLoaderLock( blackbone::Process& process, DWORD cookie )
    {
        auto ntdll = process.modules().GetModule( L"ntdll.dll" );
        if (!ntdll)
            return STATUS_DLL_NOT_FOUND;

        auto ldrUnlockResult = process.modules().GetExport( ntdll, "LdrUnlockLoaderLock" );
        if (!ldrUnlockResult.success())
            return STATUS_PROCEDURE_NOT_FOUND;

        auto ldrUnlockProc = ldrUnlockResult.result();

        process.remote().ExecDirect( ldrUnlockProc.procAddress, cookie );

        return STATUS_SUCCESS;
    }

    static bool IsLoaderLockHeld( blackbone::Process& process )
    {
        if (process.core().isWow64())
            return IsLoaderLockHeld32( process );
        else
            return IsLoaderLockHeld64( process );
    }

private:
    static bool IsLoaderLockHeld32( blackbone::Process& process )
    {
        blackbone::_PEB32 peb = { 0 };
        if (!NT_SUCCESS( process.core().peb32( &peb ) ))
            return false;

        return false;
    }

    static bool IsLoaderLockHeld64( blackbone::Process& process )
    {
        blackbone::_PEB64 peb = { 0 };
        if (!NT_SUCCESS( process.core().peb64( &peb ) ))
            return false;

        return false;
    }
};
