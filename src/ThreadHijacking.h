#pragma once

#include <Windows.h>
#include "Win11Compat.h"
#include <BlackBone/Process/Process.h>
#include <BlackBone/Process/Threads/Thread.h>
#include <vector>
#include <algorithm>

class ThreadHijacking
{
public:
    enum SelectionStrategy
    {
        MostExecuted,
        LeastExecuted,
        Random,
        MainThread,
        GUI_Thread,
        Oldest,
        Newest
    };

    static blackbone::ThreadPtr SelectThread( blackbone::Process& process, SelectionStrategy strategy )
    {
        auto& threads = process.threads();
        auto threadList = threads.getAll();

        if (threadList.empty())
            return nullptr;

        switch (strategy)
        {
            case MostExecuted:
                return threads.getMostExecuted();

            case LeastExecuted:
                return GetLeastExecuted( threadList );

            case Random:
                return threadList[rand() % threadList.size()];

            case MainThread:
                return threads.getMain();

            case GUI_Thread:
                return GetGUIThread( threadList );

            case Oldest:
                return threadList.front();

            case Newest:
                return threadList.back();

            default:
                return threads.getMostExecuted();
        }
    }

    static NTSTATUS HijackThread(
        blackbone::ThreadPtr thread,
        blackbone::Process& process,
        uint64_t entryPoint,
        uint64_t argument,
        bool waitForCompletion = true
        )
    {
        if (!thread)
            return STATUS_INVALID_HANDLE;

        if (!thread->Suspend())
            return STATUS_UNSUCCESSFUL;

#ifdef _WIN64
        blackbone::_CONTEXT64 ctx = { 0 };
        NTSTATUS status = thread->GetContext( ctx, CONTEXT64_ALL );
        if (!NT_SUCCESS( status ))
        {
            thread->Resume();
            return status;
        }

        uint64_t originalIP = ctx.Rip;
        ctx.Rip = entryPoint;
        ctx.Rcx = argument;

        status = thread->SetContext( ctx );
        if (!NT_SUCCESS( status ))
        {
            thread->Resume();
            return status;
        }

        thread->Resume();

        if (waitForCompletion)
        {
            thread->Join( INFINITE );
            thread->Suspend();

            blackbone::_CONTEXT64 restoreCtx = { 0 };
            thread->GetContext( restoreCtx, CONTEXT64_ALL );
            restoreCtx.Rip = originalIP;
            thread->SetContext( restoreCtx );
            thread->Resume();
        }
#else
        blackbone::_CONTEXT32 ctx = { 0 };
        NTSTATUS status = thread->GetContext( ctx, CONTEXT_ALL );
        if (!NT_SUCCESS( status ))
        {
            thread->Resume();
            return status;
        }

        uint32_t originalIP = ctx.Eip;
        ctx.Eip = static_cast<uint32_t>(entryPoint);

        auto stackPtr = ctx.Esp - sizeof( DWORD );
        process.memory().Write( stackPtr, sizeof( DWORD ), &argument );
        ctx.Esp = stackPtr;

        status = thread->SetContext( ctx );
        if (!NT_SUCCESS( status ))
        {
            thread->Resume();
            return status;
        }

        thread->Resume();

        if (waitForCompletion)
        {
            thread->Join( INFINITE );
            thread->Suspend();

            blackbone::_CONTEXT32 restoreCtx = { 0 };
            thread->GetContext( restoreCtx, CONTEXT_ALL );
            restoreCtx.Eip = originalIP;
            thread->SetContext( restoreCtx );
            thread->Resume();
        }
#endif

        return STATUS_SUCCESS;
    }

private:
    static blackbone::ThreadPtr GetLeastExecuted( const std::vector<blackbone::ThreadPtr>& threads )
    {
        if (threads.empty())
            return nullptr;

        return *std::min_element( threads.begin(), threads.end(),
            []( const blackbone::ThreadPtr& a, const blackbone::ThreadPtr& b ) {
                FILETIME ct1, et1, kt1, ut1;
                FILETIME ct2, et2, kt2, ut2;

                GetThreadTimes( a->handle(), &ct1, &et1, &kt1, &ut1 );
                GetThreadTimes( b->handle(), &ct2, &et2, &kt2, &ut2 );

                ULARGE_INTEGER t1, t2;
                t1.LowPart = ut1.dwLowDateTime;
                t1.HighPart = ut1.dwHighDateTime;
                t2.LowPart = ut2.dwLowDateTime;
                t2.HighPart = ut2.dwHighDateTime;

                return t1.QuadPart < t2.QuadPart;
            } );
    }

    static blackbone::ThreadPtr GetGUIThread( const std::vector<blackbone::ThreadPtr>& threads )
    {
        for (const auto& thread : threads)
        {
            GUITHREADINFO gti = { sizeof( gti ) };
            if (GetGUIThreadInfo( thread->id(), &gti ))
                return thread;
        }

        return nullptr;
    }

public:
    static SelectionStrategy GetRecommendedStrategy()
    {
        if (Win11Compat::IsWindows11OrGreater())
        {
            if (Win11Compat::IsHVCIEnabled())
                return LeastExecuted;

            return Random;
        }

        return MostExecuted;
    }

    static bool IsThreadSafe( blackbone::ThreadPtr thread )
    {
        if (!thread)
            return false;

        FILETIME ct, et, kt, ut;
        if (!GetThreadTimes( thread->handle(), &ct, &et, &kt, &ut ))
            return false;

        ULARGE_INTEGER userTime;
        userTime.LowPart = ut.dwLowDateTime;
        userTime.HighPart = ut.dwHighDateTime;

        return userTime.QuadPart > 0;
    }

    static std::vector<blackbone::ThreadPtr> GetSafeThreads( blackbone::Process& process )
    {
        auto& threads = process.threads();
        auto threadList = threads.getAll();
        std::vector<blackbone::ThreadPtr> safeThreads;

        for (const auto& thread : threadList)
        {
            if (IsThreadSafe( thread ))
                safeThreads.push_back( thread );
        }

        return safeThreads;
    }

    static NTSTATUS HijackWithFallback(
        blackbone::Process& process,
        uint64_t entryPoint,
        uint64_t argument,
        SelectionStrategy primaryStrategy = MostExecuted
        )
    {
        auto thread = SelectThread( process, primaryStrategy );
        if (!thread)
        {
            thread = SelectThread( process, Random );
            if (!thread)
                return STATUS_NOT_FOUND;
        }

        NTSTATUS status = HijackThread( thread, process, entryPoint, argument, true );

        if (!NT_SUCCESS( status ))
        {
            thread = SelectThread( process, LeastExecuted );
            if (thread)
                status = HijackThread( thread, process, entryPoint, argument, true );
        }

        return status;
    }
};
