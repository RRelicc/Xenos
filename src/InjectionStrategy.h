#pragma once

#include <Windows.h>
#include "Win11Compat.h"
#include "HookEvasion.h"
#include "ModuleCloaking.h"
#include "ThreadHijacking.h"
#include "StackSpoofer.h"
#include "SyscallResolver.h"
#include "ReflectiveLoader.h"
#include "AntiDebug.h"

class InjectionStrategy
{
public:
    struct StrategyConfig
    {
        bool useHookEvasion;
        bool useModuleCloaking;
        bool useStackSpoofing;
        bool useDirectSyscalls;
        bool useReflectiveLoading;
        bool useAntiDebug;
        ThreadHijacking::SelectionStrategy threadStrategy;
        HookEvasion::EvasionMethod evasionMethod;
    };

    static StrategyConfig GetOptimalStrategy()
    {
        StrategyConfig config = { 0 };

        auto sysInfo = Win11Compat::GetSystemInfo();

        if (sysInfo.version >= Win11Compat::WindowsVersion::Win11)
        {
            config.useHookEvasion = true;
            config.useModuleCloaking = true;
            config.useStackSpoofing = true;
            config.useAntiDebug = true;
            config.threadStrategy = ThreadHijacking::Random;
            config.evasionMethod = HookEvasion::FreshCopy;

            if (sysInfo.isHVCIEnabled || sysInfo.isKernelCETEnabled)
            {
                config.useDirectSyscalls = true;
                config.useReflectiveLoading = true;
                config.evasionMethod = HookEvasion::DirectSyscall;
            }

            if (sysInfo.isWin11_23H2OrGreater)
            {
                config.useReflectiveLoading = true;
                config.threadStrategy = ThreadHijacking::LeastExecuted;
            }
        }
        else if (sysInfo.version >= Win11Compat::WindowsVersion::Win10)
        {
            config.useHookEvasion = sysInfo.isVBSEnabled;
            config.useModuleCloaking = sysInfo.isVBSEnabled;
            config.useStackSpoofing = false;
            config.useAntiDebug = true;
            config.threadStrategy = ThreadHijacking::MostExecuted;
            config.evasionMethod = HookEvasion::UnhookNtdll;
        }
        else
        {
            config.useHookEvasion = false;
            config.useModuleCloaking = false;
            config.useStackSpoofing = false;
            config.useAntiDebug = false;
            config.threadStrategy = ThreadHijacking::MostExecuted;
            config.evasionMethod = HookEvasion::UnhookNtdll;
        }

        return config;
    }

    static StrategyConfig GetStealthyStrategy()
    {
        StrategyConfig config = GetOptimalStrategy();
        config.useHookEvasion = true;
        config.useModuleCloaking = true;
        config.useStackSpoofing = true;
        config.useDirectSyscalls = true;
        config.useReflectiveLoading = true;
        config.useAntiDebug = true;
        config.threadStrategy = ThreadHijacking::Random;
        config.evasionMethod = HookEvasion::DirectSyscall;
        return config;
    }

    static StrategyConfig GetFastStrategy()
    {
        StrategyConfig config = { 0 };
        config.useHookEvasion = false;
        config.useModuleCloaking = false;
        config.useStackSpoofing = false;
        config.useDirectSyscalls = false;
        config.useReflectiveLoading = false;
        config.useAntiDebug = false;
        config.threadStrategy = ThreadHijacking::MostExecuted;
        config.evasionMethod = HookEvasion::UnhookNtdll;
        return config;
    }

    static bool ValidateStrategy( const StrategyConfig& config )
    {
        if (config.useDirectSyscalls && !SyscallResolver::RequiresSyscalls())
            return false;

        if (config.useReflectiveLoading && !ReflectiveLoader::RequiresReflectiveLoading())
            return false;

        if (!Win11Compat::SupportsKernelInjection() && config.useDirectSyscalls)
            return false;

        return true;
    }

    static std::wstring GetStrategyDescription( const StrategyConfig& config )
    {
        std::wstring desc = L"Injection Strategy:\n";

        if (config.useHookEvasion)
            desc += L"  [+] Hook Evasion Enabled\n";

        if (config.useModuleCloaking)
            desc += L"  [+] Module Cloaking Enabled\n";

        if (config.useStackSpoofing)
            desc += L"  [+] Stack Spoofing Enabled\n";

        if (config.useDirectSyscalls)
            desc += L"  [+] Direct Syscalls Enabled\n";

        if (config.useReflectiveLoading)
            desc += L"  [+] Reflective Loading Enabled\n";

        if (config.useAntiDebug)
            desc += L"  [+] Anti-Debug Enabled\n";

        desc += L"  Thread Strategy: ";
        switch (config.threadStrategy)
        {
        case ThreadHijacking::MostExecuted: desc += L"Most Executed\n"; break;
        case ThreadHijacking::LeastExecuted: desc += L"Least Executed\n"; break;
        case ThreadHijacking::Random: desc += L"Random\n"; break;
        case ThreadHijacking::MainThread: desc += L"Main Thread\n"; break;
        case ThreadHijacking::GUI_Thread: desc += L"GUI Thread\n"; break;
        case ThreadHijacking::Oldest: desc += L"Oldest\n"; break;
        case ThreadHijacking::Newest: desc += L"Newest\n"; break;
        }

        return desc;
    }

    static StrategyConfig AdjustForTarget( HANDLE hProcess )
    {
        StrategyConfig config = GetOptimalStrategy();

        if (Win11Compat::IsCFGEnabled( hProcess ))
        {
            config.useStackSpoofing = true;
            config.useDirectSyscalls = true;
        }

        if (Win11Compat::IsHardenedProcess( hProcess ))
        {
            config.useReflectiveLoading = true;
            config.useModuleCloaking = true;
            config.evasionMethod = HookEvasion::DirectSyscall;
        }

        if (Win11Compat::IsDEPEnabled( hProcess ))
        {
            config.useStackSpoofing = true;
        }

        return config;
    }
};
