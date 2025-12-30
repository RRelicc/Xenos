#pragma once

#include "Win11Compat.h"
#include "RetryHelper.h"
#include <BlackBone/Process/Process.h>
#include <BlackBone/Process/RPC/RemoteHook.h>
#include <vector>
#include <string>

class RemoteHookEx
{
public:
    struct HookInfo
    {
        blackbone::ptr_t targetAddress = 0;
        blackbone::ptr_t hookAddress = 0;
        blackbone::ptr_t originalBytes = 0;
        std::string functionName;
        bool installed = false;
    };

    static NTSTATUS InstallRemoteHook(
        blackbone::Process& process,
        blackbone::ptr_t targetAddress,
        blackbone::ptr_t hookAddress,
        const std::string& name = ""
        )
    {
        if (Win11Compat::IsCFGEnabled( process.core().handle() ))
        {
            return STATUS_NOT_SUPPORTED;
        }

        auto result = process.hooks().Apply(
            targetAddress,
            hookAddress,
            blackbone::HookType::Inline
        );

        if (result.success())
        {
            HookInfo info;
            info.targetAddress = targetAddress;
            info.hookAddress = hookAddress;
            info.functionName = name;
            info.installed = true;
            _hooks.push_back( info );
        }

        return result.status;
    }

    static NTSTATUS RemoveRemoteHook( blackbone::Process& process, blackbone::ptr_t targetAddress )
    {
        auto result = process.hooks().Remove( targetAddress );

        if (result.success())
        {
            for (auto it = _hooks.begin(); it != _hooks.end(); ++it)
            {
                if (it->targetAddress == targetAddress)
                {
                    _hooks.erase( it );
                    break;
                }
            }
        }

        return result.status;
    }

    static NTSTATUS RemoveAllHooks( blackbone::Process& process )
    {
        NTSTATUS status = process.hooks().RemoveAll();
        _hooks.clear();
        return status;
    }

    static std::vector<HookInfo> GetInstalledHooks()
    {
        return _hooks;
    }

    static bool IsHooked( blackbone::ptr_t targetAddress )
    {
        for (const auto& hook : _hooks)
        {
            if (hook.targetAddress == targetAddress && hook.installed)
                return true;
        }

        return false;
    }

    static size_t GetHookCount()
    {
        return _hooks.size();
    }

    static NTSTATUS InstallInlineHook(
        blackbone::Process& process,
        const std::wstring& moduleName,
        const std::string& functionName,
        blackbone::ptr_t hookAddress
        )
    {
        auto mod = process.modules().GetModule( moduleName );
        if (!mod)
            return STATUS_NOT_FOUND;

        auto exp = mod->GetExport( functionName );
        if (!exp)
            return STATUS_NOT_FOUND;

        return InstallRemoteHook( process, exp->procAddress, hookAddress, functionName );
    }

    static NTSTATUS InstallVTableHook(
        blackbone::Process& process,
        blackbone::ptr_t objectAddress,
        int methodIndex,
        blackbone::ptr_t hookAddress
        )
    {
        blackbone::ptr_t vtablePtr = 0;
        if (!NT_SUCCESS( process.memory().Read( objectAddress, sizeof( vtablePtr ), &vtablePtr ) ))
            return STATUS_INVALID_ADDRESS;

        blackbone::ptr_t methodAddress = 0;
        if (!NT_SUCCESS( process.memory().Read(
            vtablePtr + methodIndex * sizeof( blackbone::ptr_t ),
            sizeof( methodAddress ),
            &methodAddress ) ))
        {
            return STATUS_INVALID_ADDRESS;
        }

        return InstallRemoteHook( process, methodAddress, hookAddress );
    }

    static NTSTATUS InstallIATHook(
        blackbone::Process& process,
        const std::wstring& moduleName,
        const std::string& importName,
        blackbone::ptr_t hookAddress
        )
    {
        auto mod = process.modules().GetModule( moduleName );
        if (!mod)
            return STATUS_NOT_FOUND;

        auto result = process.hooks().Apply(
            0,
            hookAddress,
            blackbone::HookType::IATHOOK,
            moduleName,
            blackbone::Utils::AnsiToWstring( importName )
        );

        return result.status;
    }

    static bool CanInstallHooks( blackbone::Process& process )
    {
        if (Win11Compat::IsCFGEnabled( process.core().handle() ))
            return false;

        if (Win11Compat::IsHVCIEnabled())
            return false;

        return true;
    }

    static HookInfo* FindHookByName( const std::string& name )
    {
        for (auto& hook : _hooks)
        {
            if (hook.functionName == name && hook.installed)
                return &hook;
        }

        return nullptr;
    }

    static std::vector<HookInfo> FindHooksByModule( const std::wstring& moduleName )
    {
        std::vector<HookInfo> moduleHooks;

        for (const auto& hook : _hooks)
        {
            if (hook.installed)
                moduleHooks.push_back( hook );
        }

        return moduleHooks;
    }

private:
    static std::vector<HookInfo> _hooks;
};

std::vector<RemoteHookEx::HookInfo> RemoteHookEx::_hooks;
