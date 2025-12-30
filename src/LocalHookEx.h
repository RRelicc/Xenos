#pragma once

#include "Win11Compat.h"
#include <BlackBone/LocalHook/LocalHookBase.h>
#include <vector>
#include <string>
#include <functional>
#include <memory>

class LocalHookEx
{
public:
    struct HookInfo
    {
        void* originalFunc = nullptr;
        void* hookFunc = nullptr;
        void* trampoline = nullptr;
        std::string name;
        bool active = false;
        std::unique_ptr<blackbone::DetourBase> detour;
    };

    static NTSTATUS InstallHook(
        void* targetFunc,
        void* hookFunc,
        void*& trampoline,
        const std::string& name = ""
        )
    {
        auto detour = std::make_unique<blackbone::DetourBase>();

        NTSTATUS status = detour->Hook(
            reinterpret_cast<blackbone::ptr_t>(targetFunc),
            reinterpret_cast<blackbone::ptr_t>(hookFunc)
        );

        if (NT_SUCCESS( status ))
        {
            trampoline = reinterpret_cast<void*>(detour->original());

            HookInfo info;
            info.originalFunc = targetFunc;
            info.hookFunc = hookFunc;
            info.trampoline = trampoline;
            info.name = name;
            info.active = true;
            info.detour = std::move( detour );

            _hooks.push_back( std::move( info ) );
        }

        return status;
    }

    static NTSTATUS UninstallHook( void* targetFunc )
    {
        for (auto it = _hooks.begin(); it != _hooks.end(); ++it)
        {
            if (it->originalFunc == targetFunc)
            {
                it->active = false;
                _hooks.erase( it );
                return STATUS_SUCCESS;
            }
        }

        return STATUS_NOT_FOUND;
    }

    static void UninstallAllHooks()
    {
        _hooks.clear();
    }

    static std::vector<HookInfo> GetActiveHooks()
    {
        std::vector<HookInfo> active;

        for (const auto& hook : _hooks)
        {
            if (hook.active)
                active.push_back( hook );
        }

        return active;
    }

    static bool IsHooked( void* targetFunc )
    {
        for (const auto& hook : _hooks)
        {
            if (hook.originalFunc == targetFunc && hook.active)
                return true;
        }

        return false;
    }

    static void* GetTrampoline( void* targetFunc )
    {
        for (const auto& hook : _hooks)
        {
            if (hook.originalFunc == targetFunc && hook.active)
                return hook.trampoline;
        }

        return nullptr;
    }

    static size_t GetHookCount()
    {
        return _hooks.size();
    }

    static HookInfo* FindHookByName( const std::string& name )
    {
        for (auto& hook : _hooks)
        {
            if (hook.name == name && hook.active)
                return &hook;
        }

        return nullptr;
    }

    static NTSTATUS EnableHook( void* targetFunc )
    {
        for (auto& hook : _hooks)
        {
            if (hook.originalFunc == targetFunc)
            {
                hook.active = true;
                return STATUS_SUCCESS;
            }
        }

        return STATUS_NOT_FOUND;
    }

    static NTSTATUS DisableHook( void* targetFunc )
    {
        for (auto& hook : _hooks)
        {
            if (hook.originalFunc == targetFunc)
            {
                hook.active = false;
                return STATUS_SUCCESS;
            }
        }

        return STATUS_NOT_FOUND;
    }

    static bool CanInstallHook()
    {
        if (Win11Compat::IsCFGEnabled( GetCurrentProcess() ))
            return false;

        if (Win11Compat::IsHVCIEnabled())
            return false;

        return true;
    }

private:
    static std::vector<HookInfo> _hooks;
};

std::vector<LocalHookEx::HookInfo> LocalHookEx::_hooks;
