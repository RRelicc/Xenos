#pragma once

#include "Win11Compat.h"
#include <BlackBone/Process/Process.h>
#include <string>

class ThreadNamingSpoofing
{
public:
    static NTSTATUS SetThreadName(
        blackbone::Process& process,
        DWORD threadId,
        const std::wstring& name
        )
    {
        HMODULE hNtdll = GetModuleHandleW( L"ntdll.dll" );
        if (!hNtdll)
            return STATUS_DLL_NOT_FOUND;

        typedef NTSTATUS( NTAPI* pfnNtSetInformationThread )(
            HANDLE, THREADINFOCLASS, PVOID, ULONG
            );

        auto NtSetInformationThread = reinterpret_cast<pfnNtSetInformationThread>(
            GetProcAddress( hNtdll, "NtSetInformationThread" )
            );

        if (!NtSetInformationThread)
            return STATUS_PROCEDURE_NOT_FOUND;

        HANDLE hThread = OpenThread( THREAD_SET_INFORMATION, FALSE, threadId );
        if (!hThread)
            return STATUS_INVALID_HANDLE;

        UNICODE_STRING threadName;
        RtlInitUnicodeString( &threadName, name.c_str() );

        const THREADINFOCLASS ThreadNameInformation = static_cast<THREADINFOCLASS>(38);

        NTSTATUS status = NtSetInformationThread(
            hThread,
            ThreadNameInformation,
            &threadName,
            sizeof( UNICODE_STRING )
        );

        CloseHandle( hThread );
        return status;
    }

    static NTSTATUS SpoofMainThreadName(
        blackbone::Process& process,
        const std::wstring& spoofedName
        )
    {
        auto mainThread = process.threads().getMain();
        if (!mainThread)
            return STATUS_NOT_FOUND;

        return SetThreadName( process, mainThread->id(), spoofedName );
    }

    static NTSTATUS SpoofAllThreadNames(
        blackbone::Process& process,
        const std::wstring& baseName
        )
    {
        auto threads = process.threads().getAll();
        if (threads.empty())
            return STATUS_NOT_FOUND;

        int index = 0;
        NTSTATUS lastStatus = STATUS_SUCCESS;

        for (auto& thread : threads)
        {
            std::wstring threadName = baseName + L"_" + std::to_wstring( index++ );
            NTSTATUS status = SetThreadName( process, thread->id(), threadName );

            if (!NT_SUCCESS( status ))
                lastStatus = status;
        }

        return lastStatus;
    }

    static NTSTATUS ClearThreadName(
        blackbone::Process& process,
        DWORD threadId
        )
    {
        return SetThreadName( process, threadId, L"" );
    }

    static NTSTATUS RandomizeThreadNames(
        blackbone::Process& process,
        const std::vector<std::wstring>& namePool
        )
    {
        if (namePool.empty())
            return STATUS_INVALID_PARAMETER;

        auto threads = process.threads().getAll();
        if (threads.empty())
            return STATUS_NOT_FOUND;

        NTSTATUS lastStatus = STATUS_SUCCESS;

        for (auto& thread : threads)
        {
            uint8_t randomIndex = 0;
            BCryptGenRandom( nullptr, &randomIndex, sizeof( randomIndex ), BCRYPT_USE_SYSTEM_PREFERRED_RNG );

            size_t index = randomIndex % namePool.size();
            NTSTATUS status = SetThreadName( process, thread->id(), namePool[index] );

            if (!NT_SUCCESS( status ))
                lastStatus = status;
        }

        return lastStatus;
    }

    static std::vector<std::wstring> GetLegitimateThreadNames()
    {
        return {
            L"Worker Thread",
            L"Thread Pool Worker",
            L"RPC Thread",
            L"COM Thread",
            L"Message Thread",
            L"I/O Completion",
            L"Timer Thread",
            L"Async Worker",
            L"Background Task",
            L"Service Thread"
        };
    }

    static NTSTATUS ApplyLegitimateNames( blackbone::Process& process )
    {
        return RandomizeThreadNames( process, GetLegitimateThreadNames() );
    }
};
