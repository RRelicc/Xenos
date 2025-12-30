#pragma once

#include "Win11Compat.h"
#include "MemoryGuard.h"
#include <BlackBone/Process/Process.h>
#include <Psapi.h>
#include <vector>

class CallStackSpoofer
{
public:
    struct SpoofedCall
    {
        blackbone::ptr_t originalReturnAddress = 0;
        blackbone::ptr_t spoofedReturnAddress = 0;
        blackbone::ptr_t stackPointer = 0;
    };

#ifdef _WIN64
    static blackbone::ptr_t SpoofCall(
        void* targetFunction,
        blackbone::ptr_t spoofReturnAddress,
        void* arg1 = nullptr,
        void* arg2 = nullptr,
        void* arg3 = nullptr,
        void* arg4 = nullptr
        )
    {
        uint8_t shellcode[] = {
            0x48, 0x89, 0x4C, 0x24, 0x08,                   // mov [rsp+8], rcx
            0x48, 0x89, 0x54, 0x24, 0x10,                   // mov [rsp+16], rdx
            0x4C, 0x89, 0x44, 0x24, 0x18,                   // mov [rsp+24], r8
            0x4C, 0x89, 0x4C, 0x24, 0x20,                   // mov [rsp+32], r9
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, <spoofed return>
            0x48, 0x89, 0x44, 0x24, 0x00,                   // mov [rsp], rax
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, <target function>
            0xFF, 0xE0                                      // jmp rax
        };

        *reinterpret_cast<blackbone::ptr_t*>(&shellcode[16]) = spoofReturnAddress;
        *reinterpret_cast<blackbone::ptr_t*>(&shellcode[31]) = reinterpret_cast<blackbone::ptr_t>(targetFunction);

        MemoryGuard<uint8_t> mem( sizeof( shellcode ), PAGE_EXECUTE_READWRITE );
        if (!mem)
            return 0;

        memcpy( mem.get(), shellcode, sizeof( shellcode ) );

        typedef blackbone::ptr_t( *SpoofFunc )(void*, void*, void*, void*);
        SpoofFunc func = reinterpret_cast<SpoofFunc>(mem.get());

        blackbone::ptr_t result = 0;

        __try
        {
            result = func( arg1, arg2, arg3, arg4 );
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            result = 0;
        }

        return result;
    }
#else
    static blackbone::ptr_t SpoofCall(
        void* targetFunction,
        blackbone::ptr_t spoofReturnAddress,
        void* arg1 = nullptr,
        void* arg2 = nullptr,
        void* arg3 = nullptr,
        void* arg4 = nullptr
        )
    {
        uint8_t shellcode[] = {
            0x58,                                           // pop eax (original return)
            0x68, 0x00, 0x00, 0x00, 0x00,                   // push <spoofed return>
            0xB8, 0x00, 0x00, 0x00, 0x00,                   // mov eax, <target function>
            0xFF, 0xE0                                      // jmp eax
        };

        *reinterpret_cast<uint32_t*>(&shellcode[2]) = static_cast<uint32_t>(spoofReturnAddress);
        *reinterpret_cast<uint32_t*>(&shellcode[7]) = reinterpret_cast<uint32_t>(targetFunction);

        MemoryGuard<uint8_t> mem( sizeof( shellcode ), PAGE_EXECUTE_READWRITE );
        if (!mem)
            return 0;

        memcpy( mem.get(), shellcode, sizeof( shellcode ) );

        typedef blackbone::ptr_t( __stdcall* SpoofFunc )(void*, void*, void*, void*);
        SpoofFunc func = reinterpret_cast<SpoofFunc>(mem.get());

        blackbone::ptr_t result = 0;

        __try
        {
            result = func( arg1, arg2, arg3, arg4 );
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            result = 0;
        }

        return result;
    }
#endif

    static blackbone::ptr_t GetLegitimateReturnAddress(
        const std::wstring& moduleName = L"ntdll.dll",
        const std::string& functionName = "NtClose"
        )
    {
        HMODULE hModule = GetModuleHandleW( moduleName.c_str() );
        if (!hModule)
            hModule = LoadLibraryW( moduleName.c_str() );

        if (!hModule)
            return 0;

        void* funcAddr = GetProcAddress( hModule, functionName.c_str() );
        if (!funcAddr)
            return 0;

        return reinterpret_cast<blackbone::ptr_t>(funcAddr) + 1;
    }

    static std::vector<blackbone::ptr_t> GetCurrentCallStack()
    {
        std::vector<blackbone::ptr_t> callStack;

#ifdef _WIN64
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_CONTROL;
        RtlCaptureContext( &ctx );

        blackbone::ptr_t rsp = ctx.Rsp;

        for (int i = 0; i < 64; i++)
        {
            blackbone::ptr_t* stackPtr = reinterpret_cast<blackbone::ptr_t*>(rsp + i * sizeof( blackbone::ptr_t ));

            MEMORY_BASIC_INFORMATION mbi = { 0 };
            if (!VirtualQuery( stackPtr, &mbi, sizeof( mbi ) ) ||
                mbi.State != MEM_COMMIT ||
                !(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
                break;

            blackbone::ptr_t value = *stackPtr;

            if (value > 0x10000 && value < 0x7FFFFFFF0000)
            {
                callStack.push_back( value );
            }
        }
#else
        uint32_t esp = 0;

        __asm {
            mov esp, esp
        }

        for (int i = 0; i < 64; i++)
        {
            uint32_t* stackPtr = reinterpret_cast<uint32_t*>(esp + i * sizeof( uint32_t ));

            MEMORY_BASIC_INFORMATION mbi = { 0 };
            if (!VirtualQuery( stackPtr, &mbi, sizeof( mbi ) ) ||
                mbi.State != MEM_COMMIT ||
                !(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
                break;

            uint32_t value = *stackPtr;

            if (value > 0x10000 && value < 0x7FFFFFFF)
            {
                callStack.push_back( value );
            }
        }
#endif

        return callStack;
    }

    static NTSTATUS SpoofRemoteCallStack(
        blackbone::Process& process,
        DWORD threadId,
        blackbone::ptr_t spoofAddress
        )
    {
        auto thread = process.threads().get( threadId );
        if (!thread)
            return STATUS_NOT_FOUND;

        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_FULL;

        if (!GetThreadContext( thread->handle(), &ctx ))
            return STATUS_UNSUCCESSFUL;

#ifdef _WIN64
        blackbone::ptr_t stackTop = ctx.Rsp;

        blackbone::ptr_t returnAddr = 0;
        if (!NT_SUCCESS( process.memory().Read( stackTop, sizeof( returnAddr ), &returnAddr ) ))
            return STATUS_MEMORY_NOT_ALLOCATED;

        return process.memory().Write( stackTop, sizeof( spoofAddress ), &spoofAddress );
#else
        uint32_t stackTop = ctx.Esp;

        uint32_t returnAddr = 0;
        if (!NT_SUCCESS( process.memory().Read( stackTop, sizeof( returnAddr ), &returnAddr ) ))
            return STATUS_MEMORY_NOT_ALLOCATED;

        uint32_t spoofAddr32 = static_cast<uint32_t>(spoofAddress);
        return process.memory().Write( stackTop, sizeof( spoofAddr32 ), &spoofAddr32 );
#endif
    }

    static NTSTATUS CleanCallStack(
        blackbone::Process& process,
        DWORD threadId,
        size_t framesToClean = 5
        )
    {
        auto thread = process.threads().get( threadId );
        if (!thread)
            return STATUS_NOT_FOUND;

        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_FULL;

        if (!GetThreadContext( thread->handle(), &ctx ))
            return STATUS_UNSUCCESSFUL;

#ifdef _WIN64
        blackbone::ptr_t stackTop = ctx.Rsp;

        for (size_t i = 0; i < framesToClean; i++)
        {
            blackbone::ptr_t zero = 0;
            process.memory().Write( stackTop + i * sizeof( blackbone::ptr_t ), sizeof( zero ), &zero );
        }
#else
        uint32_t stackTop = ctx.Esp;

        for (size_t i = 0; i < framesToClean; i++)
        {
            uint32_t zero = 0;
            process.memory().Write( stackTop + i * sizeof( uint32_t ), sizeof( zero ), &zero );
        }
#endif

        return STATUS_SUCCESS;
    }

    static bool IsAddressInModule(
        blackbone::ptr_t address,
        const std::wstring& moduleName
        )
    {
        HMODULE hModule = GetModuleHandleW( moduleName.c_str() );
        if (!hModule)
            return false;

        MODULEINFO modInfo = { 0 };
        if (!GetModuleInformation( GetCurrentProcess(), hModule, &modInfo, sizeof( modInfo ) ))
            return false;

        blackbone::ptr_t moduleBase = reinterpret_cast<blackbone::ptr_t>(modInfo.lpBaseOfDll);
        blackbone::ptr_t moduleEnd = moduleBase + modInfo.SizeOfImage;

        return address >= moduleBase && address < moduleEnd;
    }

    static blackbone::ptr_t FindGadgetInModule(
        const std::wstring& moduleName,
        const std::vector<uint8_t>& pattern
        )
    {
        HMODULE hModule = GetModuleHandleW( moduleName.c_str() );
        if (!hModule)
            hModule = LoadLibraryW( moduleName.c_str() );

        if (!hModule)
            return 0;

        MODULEINFO modInfo = { 0 };
        if (!GetModuleInformation( GetCurrentProcess(), hModule, &modInfo, sizeof( modInfo ) ))
            return 0;

        uint8_t* baseAddr = reinterpret_cast<uint8_t*>(modInfo.lpBaseOfDll);
        size_t moduleSize = modInfo.SizeOfImage;

        for (size_t i = 0; i < moduleSize - pattern.size(); i++)
        {
            if (memcmp( baseAddr + i, pattern.data(), pattern.size() ) == 0)
            {
                return reinterpret_cast<blackbone::ptr_t>(baseAddr + i);
            }
        }

        return 0;
    }

    static blackbone::ptr_t FindRetGadget( const std::wstring& moduleName = L"ntdll.dll" )
    {
        std::vector<uint8_t> retPattern = { 0xC3 };
        return FindGadgetInModule( moduleName, retPattern );
    }

    static blackbone::ptr_t FindJmpRaxGadget( const std::wstring& moduleName = L"ntdll.dll" )
    {
        std::vector<uint8_t> jmpRaxPattern = { 0xFF, 0xE0 };
        return FindGadgetInModule( moduleName, jmpRaxPattern );
    }
};
