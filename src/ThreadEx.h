#pragma once

#include "Win11Compat.h"
#include "ThreadHijacking.h"
#include <BlackBone/Process/Process.h>
#include <BlackBone/Process/Threads/Thread.h>
#include <vector>

class ThreadEx
{
public:
    struct ThreadInfo
    {
        DWORD tid = 0;
        blackbone::ptr_t startAddress = 0;
        blackbone::ptr_t teb = 0;
        DWORD priority = 0;
        DWORD suspendCount = 0;
        bool isMainThread = false;
        bool isSuspended = false;
        bool isWaiting = false;
    };

    static std::vector<ThreadInfo> EnumerateThreads( blackbone::Process& process )
    {
        std::vector<ThreadInfo> threads;
        auto& bbThreads = process.threads().getAll();

        for (auto& thread : bbThreads)
        {
            ThreadInfo info;
            info.tid = thread->id();
            info.startAddress = thread->startAddress();
            info.teb = thread->teb();

            THREAD_BASIC_INFORMATION tbi = { 0 };
            ULONG returnLength = 0;

            if (NT_SUCCESS( NtQueryInformationThread(
                thread->handle(),
                (THREADINFOCLASS)0,
                &tbi,
                sizeof( tbi ),
                &returnLength ) ))
            {
                info.priority = tbi.Priority;
            }

            DWORD suspendCount = SuspendThread( thread->handle() );
            if (suspendCount != (DWORD)-1)
            {
                info.suspendCount = suspendCount;
                info.isSuspended = (suspendCount > 0);
                ResumeThread( thread->handle() );
            }

            threads.push_back( info );
        }

        return threads;
    }

    static blackbone::ThreadPtr GetMainThread( blackbone::Process& process )
    {
        auto& threads = process.threads().getAll();

        for (auto& thread : threads)
        {
            if (thread->id() == process.threads().getMain())
                return thread;
        }

        return nullptr;
    }

    static std::vector<blackbone::ThreadPtr> GetSuspendedThreads( blackbone::Process& process )
    {
        std::vector<blackbone::ThreadPtr> suspended;
        auto& threads = process.threads().getAll();

        for (auto& thread : threads)
        {
            DWORD count = SuspendThread( thread->handle() );
            if (count != (DWORD)-1)
            {
                if (count > 0)
                    suspended.push_back( thread );
                ResumeThread( thread->handle() );
            }
        }

        return suspended;
    }

    static std::vector<blackbone::ThreadPtr> GetActiveThreads( blackbone::Process& process )
    {
        std::vector<blackbone::ThreadPtr> active;
        auto& threads = process.threads().getAll();

        for (auto& thread : threads)
        {
            DWORD count = SuspendThread( thread->handle() );
            if (count != (DWORD)-1)
            {
                if (count == 0)
                    active.push_back( thread );
                ResumeThread( thread->handle() );
            }
        }

        return active;
    }

    static NTSTATUS SuspendAllThreads( blackbone::Process& process, DWORD exceptTid = 0 )
    {
        auto& threads = process.threads().getAll();

        for (auto& thread : threads)
        {
            if (exceptTid != 0 && thread->id() == exceptTid)
                continue;

            thread->Suspend();
        }

        return STATUS_SUCCESS;
    }

    static NTSTATUS ResumeAllThreads( blackbone::Process& process )
    {
        auto& threads = process.threads().getAll();

        for (auto& thread : threads)
        {
            thread->Resume();
        }

        return STATUS_SUCCESS;
    }

    static NTSTATUS TerminateThread( blackbone::ThreadPtr thread, DWORD exitCode = 0 )
    {
        return thread->Terminate( exitCode );
    }

    static NTSTATUS SetThreadPriority( blackbone::ThreadPtr thread, int priority )
    {
        if (!::SetThreadPriority( thread->handle(), priority ))
            return STATUS_UNSUCCESSFUL;

        return STATUS_SUCCESS;
    }

    static NTSTATUS CreateRemoteThread(
        blackbone::Process& process,
        blackbone::ptr_t startAddress,
        blackbone::ptr_t argument,
        bool suspended = false
        )
    {
        HANDLE hThread = CreateRemoteThread(
            process.core().handle(),
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(startAddress),
            reinterpret_cast<LPVOID>(argument),
            suspended ? CREATE_SUSPENDED : 0,
            nullptr
        );

        if (!hThread)
            return STATUS_UNSUCCESSFUL;

        CloseHandle( hThread );
        return STATUS_SUCCESS;
    }

    static blackbone::ptr_t GetThreadStartAddress( blackbone::ThreadPtr thread )
    {
        return thread->startAddress();
    }

    static blackbone::ptr_t GetThreadTEB( blackbone::ThreadPtr thread )
    {
        return thread->teb();
    }

    static DWORD GetThreadID( blackbone::ThreadPtr thread )
    {
        return thread->id();
    }

    static NTSTATUS WaitForThread( blackbone::ThreadPtr thread, DWORD timeoutMs = INFINITE )
    {
        DWORD result = WaitForSingleObject( thread->handle(), timeoutMs );

        if (result == WAIT_OBJECT_0)
            return STATUS_SUCCESS;
        if (result == WAIT_TIMEOUT)
            return STATUS_TIMEOUT;

        return STATUS_UNSUCCESSFUL;
    }

    static DWORD GetThreadExitCode( blackbone::ThreadPtr thread )
    {
        DWORD exitCode = 0;
        GetExitCodeThread( thread->handle(), &exitCode );
        return exitCode;
    }

    static bool IsThreadAlive( blackbone::ThreadPtr thread )
    {
        return GetThreadExitCode( thread ) == STILL_ACTIVE;
    }

    static NTSTATUS SetHardwareBreakpoint(
        blackbone::ThreadPtr thread,
        int index,
        blackbone::ptr_t address,
        blackbone::HWBPType type,
        blackbone::HWBPLength length
        )
    {
        return thread->AddHWBP( address, type, length );
    }

    static NTSTATUS RemoveHardwareBreakpoint( blackbone::ThreadPtr thread, blackbone::ptr_t address )
    {
        return thread->RemoveHWBP( address );
    }

    static size_t GetThreadCount( blackbone::Process& process )
    {
        return process.threads().getAll().size();
    }

    static blackbone::ThreadPtr FindThreadByID( blackbone::Process& process, DWORD tid )
    {
        auto& threads = process.threads().getAll();

        for (auto& thread : threads)
        {
            if (thread->id() == tid)
                return thread;
        }

        return nullptr;
    }

    static std::vector<blackbone::ThreadPtr> FindThreadsByStartAddress(
        blackbone::Process& process,
        blackbone::ptr_t startAddress
        )
    {
        std::vector<blackbone::ThreadPtr> matches;
        auto& threads = process.threads().getAll();

        for (auto& thread : threads)
        {
            if (thread->startAddress() == startAddress)
                matches.push_back( thread );
        }

        return matches;
    }
};
