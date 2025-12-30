#pragma once

#include "Win11Compat.h"
#include <BlackBone/Process/Process.h>
#include <BlackBone/DriverControl/DriverControl.h>

class ProcessGuard
{
public:
    ProcessGuard( blackbone::Process& process, DWORD pid, DWORD access = PROCESS_ALL_ACCESS )
        : _process( process )
        , _attached( false )
    {
        _status = _process.Attach( pid, access );
        _attached = NT_SUCCESS( _status );
    }

    ProcessGuard( blackbone::Process& process, DWORD pid, bool escalate )
        : _process( process )
        , _attached( false )
    {
        if (escalate)
        {
            _status = _process.Attach( pid, PROCESS_QUERY_LIMITED_INFORMATION );
            if (NT_SUCCESS( _status ))
            {
                _status = blackbone::Driver().PromoteHandle(
                    GetCurrentProcessId(),
                    _process.core().handle(),
                    DEFAULT_ACCESS_P | PROCESS_QUERY_LIMITED_INFORMATION
                    );
                if (NT_SUCCESS( _status ))
                    _process.EnsureInit();
            }
        }
        else
        {
            _status = _process.Attach( pid );
        }

        _attached = NT_SUCCESS( _status );
    }

    ~ProcessGuard()
    {
        if (_attached && _process.core().handle())
            _process.Detach();
    }

    NTSTATUS status() const { return _status; }
    bool attached() const { return _attached; }

    void release()
    {
        _attached = false;
    }

    blackbone::Process& process() { return _process; }

    static DWORD GetRecommendedAccess( DWORD pid )
    {
        HANDLE hProcess = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid );
        if (!hProcess)
            return PROCESS_ALL_ACCESS;

        DWORD access = PROCESS_ALL_ACCESS;

        if (Win11Compat::IsCFGEnabled( hProcess ))
        {
            access = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                     PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD;
        }

        CloseHandle( hProcess );
        return access;
    }

    static bool RequiresEscalation( DWORD pid )
    {
        if (!Win11Compat::IsProcessElevated())
            return false;

        HANDLE hProcess = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid );
        if (!hProcess)
            return true;

        bool needsEscalation = Win11Compat::IsHardenedProcess( hProcess );
        CloseHandle( hProcess );

        return needsEscalation;
    }

    ProcessGuard( const ProcessGuard& ) = delete;
    ProcessGuard& operator=( const ProcessGuard& ) = delete;

private:
    blackbone::Process& _process;
    NTSTATUS _status;
    bool _attached;
};
