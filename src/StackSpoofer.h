#pragma once

#include <Windows.h>
#include <vector>
#include "Win11Compat.h"
#include <BlackBone/Process/Process.h>

class StackSpoofer
{
public:
    static std::vector<uint8_t> GenerateSpoofedCall( uint64_t targetFunction, uint64_t returnAddress )
    {
#ifdef _WIN64
        std::vector<uint8_t> shellcode = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x50,
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xE0
        };

        *reinterpret_cast<uint64_t*>(&shellcode[2]) = returnAddress;
        *reinterpret_cast<uint64_t*>(&shellcode[13]) = targetFunction;
#else
        std::vector<uint8_t> shellcode = {
            0x68, 0x00, 0x00, 0x00, 0x00,
            0xB8, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xE0
        };

        *reinterpret_cast<uint32_t*>(&shellcode[1]) = static_cast<uint32_t>(returnAddress);
        *reinterpret_cast<uint32_t*>(&shellcode[6]) = static_cast<uint32_t>(targetFunction);
#endif

        return shellcode;
    }

    static NTSTATUS ExecuteWithSpoofedStack(
        blackbone::Process& process,
        uint64_t targetFunction,
        uint64_t fakeReturnAddress,
        const std::vector<uint64_t>& args
        )
    {
        auto shellcode = GenerateSpoofedCall( targetFunction, fakeReturnAddress );

        auto allocResult = process.memory().Allocate( shellcode.size(), PAGE_EXECUTE_READWRITE );
        if (!allocResult.success())
            return allocResult.status;

        blackbone::ptr_t shellcodeAddr = allocResult.result();

        NTSTATUS status = process.memory().Write( shellcodeAddr, shellcode.size(), shellcode.data() );
        if (!NT_SUCCESS( status ))
        {
            process.memory().Free( shellcodeAddr );
            return status;
        }

        auto threadResult = process.threads().CreateNew( shellcodeAddr, 0 );
        if (!threadResult.success())
        {
            process.memory().Free( shellcodeAddr );
            return threadResult.status;
        }

        auto thread = threadResult.result();
        thread->Join( INFINITE );

        process.memory().Free( shellcodeAddr );

        return STATUS_SUCCESS;
    }

    static std::vector<uint8_t> CreateFakeCallStack( const std::vector<uint64_t>& returnAddresses )
    {
        std::vector<uint8_t> stack;

#ifdef _WIN64
        for (auto addr : returnAddresses)
        {
            for (int i = 0; i < 8; i++)
                stack.push_back( static_cast<uint8_t>((addr >> (i * 8)) & 0xFF) );
        }
#else
        for (auto addr : returnAddresses)
        {
            for (int i = 0; i < 4; i++)
                stack.push_back( static_cast<uint8_t>((addr >> (i * 8)) & 0xFF) );
        }
#endif

        return stack;
    }

    static bool RequiresStackSpoofing()
    {
        return Win11Compat::IsWindows11OrGreater() ||
               Win11Compat::RequiresEnhancedEvasion();
    }

    static std::vector<uint64_t> GetLegitimateReturnAddresses( blackbone::Process& process )
    {
        std::vector<uint64_t> addresses;

        auto ntdll = process.modules().GetModule( L"ntdll.dll" );
        if (ntdll)
        {
            addresses.push_back( ntdll->baseAddress + 0x1000 );
            addresses.push_back( ntdll->baseAddress + 0x2000 );
            addresses.push_back( ntdll->baseAddress + 0x3000 );
        }

        auto kernel32 = process.modules().GetModule( L"kernel32.dll" );
        if (kernel32)
        {
            addresses.push_back( kernel32->baseAddress + 0x1000 );
            addresses.push_back( kernel32->baseAddress + 0x2000 );
        }

        return addresses;
    }

    static NTSTATUS ExecuteWithLegitStack(
        blackbone::Process& process,
        uint64_t targetFunction,
        const std::vector<uint64_t>& args
        )
    {
        auto fakeAddresses = GetLegitimateReturnAddresses( process );
        if (fakeAddresses.empty())
            return STATUS_NOT_FOUND;

        return ExecuteWithSpoofedStack( process, targetFunction, fakeAddresses[0], args );
    }
};
