#pragma once

#include "Win11Compat.h"
#include "HookEvasion.h"
#include "SyscallResolver.h"
#include "PPLBypass.h"
#include <BlackBone/Process/Process.h>

class SecurityBypass
{
public:
    enum BypassMethod
    {
        None = 0,
        UnhookNtdll,
        DirectSyscalls,
        FreshNtdllCopy,
        PPLBypassMethod,
        DriverAssisted,
        Combined
    };

    static BypassMethod GetRecommendedMethod( blackbone::Process& process )
    {
        HANDLE hProcess = process.core().handle();

        if (Win11Compat::IsHVCIEnabled())
            return DirectSyscalls;

        if (Win11Compat::IsCFGEnabled( hProcess ))
            return FreshNtdllCopy;

        if (Win11Compat::RequiresEnhancedEvasion())
            return Combined;

        return UnhookNtdll;
    }

    static NTSTATUS ApplyBypass( blackbone::Process& process, BypassMethod method )
    {
        switch (method)
        {
        case UnhookNtdll:
            return HookEvasion::UnhookNtdll( process );

        case DirectSyscalls:
            return SyscallResolver::Instance().PreloadCommonSyscalls();

        case FreshNtdllCopy:
            return HookEvasion::LoadFreshNtdll( process );

        case Combined:
        {
            NTSTATUS status = HookEvasion::UnhookNtdll( process );
            if (!NT_SUCCESS( status ))
                return status;
            return SyscallResolver::Instance().PreloadCommonSyscalls();
        }

        default:
            return STATUS_SUCCESS;
        }
    }

    static bool RequiresBypass( blackbone::Process& process )
    {
        return HookEvasion::IsEvasionRequired() ||
               Win11Compat::RequiresEnhancedEvasion();
    }

    static NTSTATUS BypassPPL( DWORD pid, HANDLE& outHandle )
    {
        if (!Win11Compat::IsVBSEnabled() && !Win11Compat::IsHVCIEnabled())
        {
            return PPLBypass::BypassPPLWithVBSCheck( pid, &outHandle );
        }

        return STATUS_NOT_SUPPORTED;
    }

    static bool CanBypassPPL()
    {
        if (Win11Compat::IsVBSEnabled())
            return false;

        if (Win11Compat::IsHVCIEnabled())
            return false;

        if (!Win11Compat::IsProcessElevated())
            return false;

        return true;
    }

    static NTSTATUS DisableCallbacks( blackbone::Process& process )
    {
        NTSTATUS status = STATUS_SUCCESS;

        if (Win11Compat::IsCFGEnabled( process.core().handle() ))
        {
            return STATUS_NOT_SUPPORTED;
        }

        return status;
    }

    static NTSTATUS RemoveInstrumentation( blackbone::Process& process )
    {
        return HookEvasion::RemoveInstrumentation( process );
    }

    static std::wstring GetBypassMethodName( BypassMethod method )
    {
        switch (method)
        {
        case None:              return L"None";
        case UnhookNtdll:       return L"Unhook NTDLL";
        case DirectSyscalls:    return L"Direct Syscalls";
        case FreshNtdllCopy:    return L"Fresh NTDLL Copy";
        case PPLBypassMethod:   return L"PPL Bypass";
        case DriverAssisted:    return L"Driver Assisted";
        case Combined:          return L"Combined Methods";
        }

        return L"Unknown";
    }

    static bool IsMethodAvailable( BypassMethod method )
    {
        switch (method)
        {
        case None:
            return true;

        case UnhookNtdll:
        case FreshNtdllCopy:
            return !Win11Compat::IsHVCIEnabled();

        case DirectSyscalls:
            return SyscallResolver::Instance().RequiresSyscalls();

        case PPLBypassMethod:
            return CanBypassPPL();

        case DriverAssisted:
            return Win11Compat::IsProcessElevated();

        case Combined:
            return IsMethodAvailable( UnhookNtdll ) &&
                   IsMethodAvailable( DirectSyscalls );
        }

        return false;
    }

    static std::vector<BypassMethod> GetAvailableMethods()
    {
        std::vector<BypassMethod> methods;

        for (int i = None; i <= Combined; ++i)
        {
            BypassMethod method = static_cast<BypassMethod>(i);
            if (IsMethodAvailable( method ))
                methods.push_back( method );
        }

        return methods;
    }
};
