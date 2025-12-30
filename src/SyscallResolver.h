#pragma once

#include <Windows.h>
#include <string>
#include <unordered_map>
#include <vector>
#include "Win11Compat.h"

class SyscallResolver
{
public:
    static SyscallResolver& Instance()
    {
        static SyscallResolver instance;
        return instance;
    }

    WORD GetSyscallNumber( const std::string& functionName )
    {
        auto it = _cache.find( functionName );
        if (it != _cache.end())
            return it->second;

        WORD number = 0;
        if (ResolveSyscall( functionName, &number ))
        {
            _cache[functionName] = number;
            return number;
        }

        return 0xFFFF;
    }

    std::vector<uint8_t> GetSyscallStub( const std::string& functionName )
    {
        WORD number = GetSyscallNumber( functionName );
        if (number == 0xFFFF)
            return {};

        return GenerateStub( number );
    }

private:
    SyscallResolver() = default;
    std::unordered_map<std::string, WORD> _cache;

    bool ResolveSyscall( const std::string& functionName, WORD* outNumber )
    {
        auto ntdll = GetModuleHandleW( L"ntdll.dll" );
        if (!ntdll)
            return false;

        auto funcAddr = reinterpret_cast<uint8_t*>( GetProcAddress( ntdll, functionName.c_str() ) );
        if (!funcAddr)
            return false;

#ifdef _WIN64
        if (funcAddr[0] == 0x4C && funcAddr[1] == 0x8B && funcAddr[2] == 0xD1 && funcAddr[3] == 0xB8)
        {
            *outNumber = *reinterpret_cast<WORD*>(funcAddr + 4);
            return true;
        }

        if (funcAddr[0] == 0xB8)
        {
            *outNumber = *reinterpret_cast<WORD*>(funcAddr + 1);
            return true;
        }
#else
        if (funcAddr[0] == 0xB8)
        {
            *outNumber = *reinterpret_cast<WORD*>(funcAddr + 1);
            return true;
        }
#endif

        return false;
    }

    std::vector<uint8_t> GenerateStub( WORD syscallNumber )
    {
#ifdef _WIN64
        return {
            0x4C, 0x8B, 0xD1,
            0xB8, static_cast<uint8_t>(syscallNumber & 0xFF), static_cast<uint8_t>((syscallNumber >> 8) & 0xFF), 0x00, 0x00,
            0x0F, 0x05,
            0xC3
        };
#else
        return {
            0xB8, static_cast<uint8_t>(syscallNumber & 0xFF), static_cast<uint8_t>((syscallNumber >> 8) & 0xFF), 0x00, 0x00,
            0xBA, 0x00, 0x03, 0xFE, 0x7F,
            0xFF, 0x12,
            0xC2, 0x14, 0x00
        };
#endif
    }

    SyscallResolver( const SyscallResolver& ) = delete;
    SyscallResolver& operator=( const SyscallResolver& ) = delete;

public:
    void ClearCache()
    {
        _cache.clear();
    }

    static bool RequiresSyscalls()
    {
        return Win11Compat::IsWindows11OrGreater() ||
               Win11Compat::IsHVCIEnabled() ||
               Win11Compat::RequiresEnhancedEvasion();
    }

    std::vector<std::string> GetCommonSyscalls()
    {
        return {
            "NtCreateThreadEx",
            "NtAllocateVirtualMemory",
            "NtWriteVirtualMemory",
            "NtProtectVirtualMemory",
            "NtQueryInformationProcess",
            "NtSetInformationProcess",
            "NtOpenProcess",
            "NtClose",
            "NtResumeThread",
            "NtSuspendThread",
            "NtGetContextThread",
            "NtSetContextThread"
        };
    }

    void PreloadCommonSyscalls()
    {
        for (const auto& syscall : GetCommonSyscalls())
        {
            GetSyscallNumber( syscall );
        }
    }

    bool IsSyscallAvailable( const std::string& functionName )
    {
        return GetSyscallNumber( functionName ) != 0xFFFF;
    }
};
