#pragma once

#include "Win11Compat.h"
#include "RetryHelper.h"
#include "ThreadHijacking.h"
#include <BlackBone/Process/Process.h>
#include <functional>

class RemoteExecEx
{
public:
    static NTSTATUS CreateRPCEnvironmentSafe(
        blackbone::Process& process,
        blackbone::WorkerThreadMode mode = blackbone::Worker_CreateNew
        )
    {
        if (Win11Compat::IsHVCIEnabled())
        {
            if (mode == blackbone::Worker_CreateNew)
                return process.remote().CreateRPCEnvironment( mode, true );
            else
                return STATUS_NOT_SUPPORTED;
        }

        return process.remote().CreateRPCEnvironment( mode, true );
    }

    static NTSTATUS ExecInNewThreadSafe(
        blackbone::Process& process,
        PVOID pCode,
        size_t size,
        uint64_t& result,
        blackbone::eThreadModeSwitch modeSwitch = blackbone::AutoSwitch
        )
    {
        if (Win11Compat::IsCFGEnabled( process.core().handle() ))
        {
            MEMORY_BASIC_INFORMATION mbi = { 0 };
            if (VirtualQueryEx( process.core().handle(), pCode, &mbi, sizeof( mbi ) ))
            {
                if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
                {
                    return STATUS_ACCESS_VIOLATION;
                }
            }
        }

        return RetryHelper::Retry(
            [&]() { return process.remote().ExecInNewThread( pCode, size, result, modeSwitch ); },
            RetryHelper::GetRecommendedRetries(),
            RetryHelper::GetRecommendedDelay(),
            RetryHelper::IsRetryableStatus
        );
    }

    static NTSTATUS ExecInWorkerThreadSafe(
        blackbone::Process& process,
        PVOID pCode,
        size_t size,
        uint64_t& result
        )
    {
        return RetryHelper::Retry(
            [&]() { return process.remote().ExecInWorkerThread( pCode, size, result ); },
            RetryHelper::GetRecommendedRetries(),
            RetryHelper::GetRecommendedDelay(),
            RetryHelper::IsRetryableStatus
        );
    }

    static NTSTATUS ExecInAnyThreadSafe(
        blackbone::Process& process,
        PVOID pCode,
        size_t size,
        uint64_t& result
        )
    {
        auto threads = ThreadHijacking::GetSafeThreads( process );

        if (threads.empty())
            return STATUS_NOT_FOUND;

        auto selectedThread = ThreadHijacking::SelectBestThread(
            process,
            ThreadHijacking::GetRecommendedStrategy()
        );

        if (!selectedThread)
            return STATUS_NOT_FOUND;

        return RetryHelper::Retry(
            [&]() { return process.remote().ExecInAnyThread( pCode, size, result, selectedThread ); },
            RetryHelper::GetRecommendedRetries(),
            RetryHelper::GetRecommendedDelay(),
            RetryHelper::IsRetryableStatus
        );
    }

    static NTSTATUS ExecDirectSafe(
        blackbone::Process& process,
        blackbone::ptr_t pCode,
        blackbone::ptr_t arg,
        DWORD& exitCode
        )
    {
        if (Win11Compat::IsCFGEnabled( process.core().handle() ))
        {
            MEMORY_BASIC_INFORMATION mbi = { 0 };
            if (VirtualQueryEx( process.core().handle(),
                              reinterpret_cast<LPCVOID>(pCode),
                              &mbi,
                              sizeof( mbi ) ))
            {
                if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
                {
                    return STATUS_ACCESS_VIOLATION;
                }
            }
        }

        exitCode = process.remote().ExecDirect( pCode, arg );
        return STATUS_SUCCESS;
    }

    template<typename Ret, typename... Args>
    static blackbone::call_result_t<Ret> CallFunctionSafe(
        blackbone::Process& process,
        const std::wstring& moduleName,
        const char* functionName,
        Args... args
        )
    {
        auto mod = process.modules().GetModule( moduleName );
        if (!mod)
            return blackbone::call_result_t<Ret>( Ret(), STATUS_NOT_FOUND );

        auto exportData = mod->GetExport( functionName );
        if (!exportData)
            return blackbone::call_result_t<Ret>( Ret(), STATUS_NOT_FOUND );

        Ret result = Ret();
        NTSTATUS status = RetryHelper::Retry(
            [&]()
            {
                auto callResult = process.remote().ExecDirect( exportData->procAddress, 0 );
                result = static_cast<Ret>(callResult);
                return STATUS_SUCCESS;
            },
            RetryHelper::GetRecommendedRetries(),
            RetryHelper::GetRecommendedDelay()
        );

        return blackbone::call_result_t<Ret>( result, status );
    }

    static bool IsRPCEnvironmentActive( blackbone::Process& process )
    {
        auto& threads = process.threads().getAll();

        for (auto& thread : threads)
        {
            wchar_t name[256] = { 0 };
            if (GetThreadDescription( thread->handle(), &name ) == S_OK)
            {
                std::wstring threadName( name );
                if (threadName.find( L"RPC" ) != std::wstring::npos)
                    return true;
            }
        }

        return false;
    }

    static NTSTATUS TerminateRPCEnvironment( blackbone::Process& process )
    {
        auto& threads = process.threads().getAll();
        NTSTATUS status = STATUS_NOT_FOUND;

        for (auto& thread : threads)
        {
            wchar_t name[256] = { 0 };
            if (GetThreadDescription( thread->handle(), &name ) == S_OK)
            {
                std::wstring threadName( name );
                if (threadName.find( L"RPC" ) != std::wstring::npos)
                {
                    status = thread->Terminate( 0 );
                }
            }
        }

        return status;
    }

    static size_t GetRPCDataSize( blackbone::Process& process )
    {
        return ARGS_OFFSET + 0x1000;
    }

    static NTSTATUS ValidateCodeRegion(
        blackbone::Process& process,
        blackbone::ptr_t codeAddress,
        size_t codeSize
        )
    {
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        if (!VirtualQueryEx( process.core().handle(),
                           reinterpret_cast<LPCVOID>(codeAddress),
                           &mbi,
                           sizeof( mbi ) ))
        {
            return STATUS_INVALID_ADDRESS;
        }

        if (mbi.State != MEM_COMMIT)
            return STATUS_INVALID_ADDRESS;

        if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        {
            return STATUS_ACCESS_VIOLATION;
        }

        if (mbi.RegionSize < codeSize)
            return STATUS_BUFFER_TOO_SMALL;

        return STATUS_SUCCESS;
    }

    static blackbone::WorkerThreadMode GetRecommendedWorkerMode()
    {
        if (Win11Compat::IsHVCIEnabled())
            return blackbone::Worker_CreateNew;

        if (Win11Compat::IsCFGEnabled( GetCurrentProcess() ))
            return blackbone::Worker_CreateNew;

        if (Win11Compat::RequiresEnhancedEvasion())
            return blackbone::Worker_CreateNew;

        return blackbone::Worker_UseExisting;
    }
};
