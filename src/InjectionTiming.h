#pragma once

#include <Windows.h>
#include <BlackBone/Process/Process.h>
#include <vector>
#include <string>

class InjectionTiming
{
public:
    enum Trigger
    {
        Immediate,
        OnModuleLoad,
        OnWindowCreate,
        AfterDelay,
        OnAPICall
    };

    struct TimingConfig
    {
        Trigger trigger = Immediate;
        std::wstring moduleName;
        std::wstring windowClass;
        DWORD delayMs = 0;
        std::string apiName;
    };

    static NTSTATUS WaitForCondition( blackbone::Process& process, const TimingConfig& config )
    {
        switch (config.trigger)
        {
            case Immediate:
                return STATUS_SUCCESS;

            case OnModuleLoad:
                return WaitForModuleLoad( process, config.moduleName );

            case OnWindowCreate:
                return WaitForWindowCreate( process, config.windowClass );

            case AfterDelay:
                Sleep( config.delayMs );
                return STATUS_SUCCESS;

            case OnAPICall:
                return WaitForAPICall( process, config.apiName );

            default:
                return STATUS_SUCCESS;
        }
    }

private:
    static NTSTATUS WaitForModuleLoad( blackbone::Process& process, const std::wstring& moduleName )
    {
        const DWORD timeout = 30000;
        const DWORD checkInterval = 100;
        DWORD elapsed = 0;

        while (elapsed < timeout)
        {
            auto mod = process.modules().GetModule( moduleName );
            if (mod)
                return STATUS_SUCCESS;

            Sleep( checkInterval );
            elapsed += checkInterval;
        }

        return STATUS_TIMEOUT;
    }

    static NTSTATUS WaitForWindowCreate( blackbone::Process& process, const std::wstring& windowClass )
    {
        const DWORD timeout = 30000;
        const DWORD checkInterval = 100;
        DWORD elapsed = 0;
        DWORD pid = process.pid();

        while (elapsed < timeout)
        {
            HWND hwnd = FindWindowExW( nullptr, nullptr, windowClass.c_str(), nullptr );
            if (hwnd)
            {
                DWORD windowPid = 0;
                GetWindowThreadProcessId( hwnd, &windowPid );

                if (windowPid == pid)
                    return STATUS_SUCCESS;
            }

            Sleep( checkInterval );
            elapsed += checkInterval;
        }

        return STATUS_TIMEOUT;
    }

    static NTSTATUS WaitForAPICall( blackbone::Process& process, const std::string& apiName )
    {
        return STATUS_NOT_IMPLEMENTED;
    }
};
