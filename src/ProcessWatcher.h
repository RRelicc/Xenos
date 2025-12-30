#pragma once

#include <Windows.h>
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <unordered_set>
#include <BlackBone/Process/Process.h>

class ProcessWatcher
{
public:
    using ProcessCallback = std::function<void( DWORD pid, const std::wstring& name )>;

    ProcessWatcher()
        : _stopEvent( CreateEventW( nullptr, TRUE, FALSE, nullptr ) )
        , _running( false )
    {
    }

    ~ProcessWatcher()
    {
        Stop();
        if (_stopEvent)
            CloseHandle( _stopEvent );
    }

    bool Start( const std::wstring& processName, ProcessCallback callback, DWORD skipCount = 0 )
    {
        if (_running)
            return false;

        _processName = processName;
        _callback = callback;
        _skipCount = skipCount;
        _skipped = 0;
        _running = true;

        ResetEvent( _stopEvent );
        _watchThread = std::thread( &ProcessWatcher::WatchThreadProc, this );

        return true;
    }

    void Stop()
    {
        if (!_running)
            return;

        _running = false;
        SetEvent( _stopEvent );

        if (_watchThread.joinable())
            _watchThread.join();
    }

    HANDLE GetStopEvent() const { return _stopEvent; }

private:
    void WatchThreadProc()
    {
        auto initialProcs = blackbone::Process::EnumByNameOrPID( 0, _processName ).result( std::vector<blackbone::ProcessInfo>() );
        std::unordered_set<DWORD> seenPids;

        for (const auto& proc : initialProcs)
            seenPids.insert( proc.pid );

        HANDLE notifyHandle = nullptr;
        if (RegisterProcessNotification( &notifyHandle ))
        {
            HANDLE waitHandles[] = { _stopEvent, notifyHandle };

            while (_running)
            {
                DWORD result = WaitForMultipleObjects( 2, waitHandles, FALSE, 1000 );

                if (result == WAIT_OBJECT_0)
                    break;

                if (result == WAIT_OBJECT_0 + 1 || result == WAIT_TIMEOUT)
                {
                    auto currentProcs = blackbone::Process::EnumByNameOrPID( 0, _processName ).result( std::vector<blackbone::ProcessInfo>() );

                    for (const auto& proc : currentProcs)
                    {
                        if (seenPids.find( proc.pid ) == seenPids.end())
                        {
                            if (_skipped < _skipCount)
                            {
                                _skipped++;
                                seenPids.insert( proc.pid );
                                continue;
                            }

                            if (_callback)
                                _callback( proc.pid, proc.imageName );

                            seenPids.insert( proc.pid );
                        }
                    }
                }
            }

            UnregisterProcessNotification( notifyHandle );
        }
        else
        {
            PollingFallback( initialProcs );
        }
    }

    bool RegisterProcessNotification( HANDLE* outHandle )
    {
        typedef NTSTATUS( NTAPI* pfnNtQueryInformationProcess )(
            HANDLE ProcessHandle,
            DWORD ProcessInformationClass,
            PVOID ProcessInformation,
            ULONG ProcessInformationLength,
            PULONG ReturnLength
            );

        *outHandle = CreateEventW( nullptr, FALSE, FALSE, nullptr );
        return *outHandle != nullptr;
    }

    void UnregisterProcessNotification( HANDLE handle )
    {
        if (handle)
            CloseHandle( handle );
    }

    void PollingFallback( std::vector<blackbone::ProcessInfo>& initialProcs )
    {
        while (_running)
        {
            if (WaitForSingleObject( _stopEvent, PROCESS_WAIT_SLEEP_MS ) == WAIT_OBJECT_0)
                break;

            auto currentProcs = blackbone::Process::EnumByNameOrPID( 0, _processName ).result( std::vector<blackbone::ProcessInfo>() );

            for (const auto& proc : currentProcs)
            {
                bool isNew = std::find_if( initialProcs.begin(), initialProcs.end(),
                    [&]( const blackbone::ProcessInfo& p ) { return p.pid == proc.pid; } ) == initialProcs.end();

                if (isNew)
                {
                    if (_skipped < _skipCount)
                    {
                        _skipped++;
                        initialProcs.push_back( proc );
                        continue;
                    }

                    if (_callback)
                        _callback( proc.pid, proc.imageName );

                    initialProcs = currentProcs;
                }
            }
        }
    }

    static constexpr DWORD PROCESS_WAIT_SLEEP_MS = 100;

    HANDLE _stopEvent;
    std::thread _watchThread;
    std::atomic<bool> _running;
    std::wstring _processName;
    ProcessCallback _callback;
    DWORD _skipCount;
    DWORD _skipped;

    ProcessWatcher( const ProcessWatcher& ) = delete;
    ProcessWatcher& operator=( const ProcessWatcher& ) = delete;
};
