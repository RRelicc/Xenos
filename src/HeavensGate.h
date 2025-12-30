#pragma once

#include "Win11Compat.h"
#include <BlackBone/Process/Process.h>

class HeavensGate
{
public:
    static bool IsAvailable()
    {
#ifdef _WIN64
        return false;
#else
        BOOL isWow64 = FALSE;
        IsWow64Process( GetCurrentProcess(), &isWow64 );
        return isWow64 == TRUE;
#endif
    }

    static blackbone::ptr_t ExecuteSyscall64(
        DWORD syscallNumber,
        blackbone::ptr_t arg1 = 0,
        blackbone::ptr_t arg2 = 0,
        blackbone::ptr_t arg3 = 0,
        blackbone::ptr_t arg4 = 0
        )
    {
#ifdef _WIN64
        return 0;
#else
        if (!IsAvailable())
            return 0;

        uint8_t code[] = {
            0x6A, 0x33,                         // push 0x33
            0xE8, 0x00, 0x00, 0x00, 0x00,       // call $+5
            0x83, 0x04, 0x24, 0x05,             // add dword [esp], 5
            0xCB,                               // retf
            0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28
            0x48, 0x89, 0xC8,                   // mov rax, rcx
            0x4C, 0x89, 0xC1,                   // mov rcx, r8
            0x4C, 0x89, 0xCA,                   // mov rdx, r9
            0x4D, 0x89, 0xD0,                   // mov r8, r10
            0x4D, 0x89, 0xD9,                   // mov r9, r11
            0x0F, 0x05,                         // syscall
            0x48, 0x83, 0xC4, 0x28,             // add rsp, 0x28
            0xE8, 0x00, 0x00, 0x00, 0x00,       // call $+5
            0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00, // mov dword [rsp+4], 0x23
            0x83, 0x04, 0x24, 0x0D,             // add dword [esp], 0x0D
            0xCB,                               // retf
            0xC3                                // ret
        };

        void* mem = VirtualAlloc( nullptr, sizeof( code ), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
        if (!mem)
            return 0;

        memcpy( mem, code, sizeof( code ) );

        typedef NTSTATUS( __stdcall* SyscallFunc )(DWORD, PVOID, PVOID, PVOID, PVOID);
        SyscallFunc func = reinterpret_cast<SyscallFunc>(mem);

        NTSTATUS result = func(
            syscallNumber,
            reinterpret_cast<PVOID>(arg1),
            reinterpret_cast<PVOID>(arg2),
            reinterpret_cast<PVOID>(arg3),
            reinterpret_cast<PVOID>(arg4)
        );

        VirtualFree( mem, 0, MEM_RELEASE );

        return result;
#endif
    }

    static NTSTATUS NtOpenProcess64(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PCLIENT_ID ClientId
        )
    {
#ifdef _WIN64
        return STATUS_NOT_SUPPORTED;
#else
        const DWORD syscallNumber = 0x26;

        return static_cast<NTSTATUS>(ExecuteSyscall64(
            syscallNumber,
            reinterpret_cast<blackbone::ptr_t>(ProcessHandle),
            DesiredAccess,
            reinterpret_cast<blackbone::ptr_t>(ObjectAttributes),
            reinterpret_cast<blackbone::ptr_t>(ClientId)
        ));
#endif
    }

    static NTSTATUS NtAllocateVirtualMemory64(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
        )
    {
#ifdef _WIN64
        return STATUS_NOT_SUPPORTED;
#else
        const DWORD syscallNumber = 0x18;

        return static_cast<NTSTATUS>(ExecuteSyscall64(
            syscallNumber,
            reinterpret_cast<blackbone::ptr_t>(ProcessHandle),
            reinterpret_cast<blackbone::ptr_t>(BaseAddress),
            ZeroBits,
            reinterpret_cast<blackbone::ptr_t>(RegionSize)
        ));
#endif
    }

    static NTSTATUS NtWriteVirtualMemory64(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToWrite,
        PSIZE_T NumberOfBytesWritten
        )
    {
#ifdef _WIN64
        return STATUS_NOT_SUPPORTED;
#else
        const DWORD syscallNumber = 0x3A;

        return static_cast<NTSTATUS>(ExecuteSyscall64(
            syscallNumber,
            reinterpret_cast<blackbone::ptr_t>(ProcessHandle),
            reinterpret_cast<blackbone::ptr_t>(BaseAddress),
            reinterpret_cast<blackbone::ptr_t>(Buffer),
            NumberOfBytesToWrite
        ));
#endif
    }

    static NTSTATUS NtCreateThreadEx64(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE ProcessHandle,
        PVOID StartRoutine,
        PVOID Argument,
        ULONG CreateFlags,
        SIZE_T ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximumStackSize,
        PVOID AttributeList
        )
    {
#ifdef _WIN64
        return STATUS_NOT_SUPPORTED;
#else
        const DWORD syscallNumber = 0xB7;

        uint8_t code[] = {
            0x6A, 0x33,
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0x83, 0x04, 0x24, 0x05,
            0xCB,
            0x48, 0x83, 0xEC, 0x58,
            0x48, 0x89, 0xC8,
            0x4C, 0x89, 0xC1,
            0x4C, 0x89, 0xCA,
            0x4D, 0x89, 0xD0,
            0x4D, 0x89, 0xD9,
            0x0F, 0x05,
            0x48, 0x83, 0xC4, 0x58,
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00,
            0x83, 0x04, 0x24, 0x0D,
            0xCB,
            0xC3
        };

        void* mem = VirtualAlloc( nullptr, sizeof( code ), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
        if (!mem)
            return STATUS_MEMORY_NOT_ALLOCATED;

        memcpy( mem, code, sizeof( code ) );

        typedef NTSTATUS( __stdcall* NtCreateThreadExFunc )(
            DWORD, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
            PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID
            );

        NtCreateThreadExFunc func = reinterpret_cast<NtCreateThreadExFunc>(mem);

        NTSTATUS result = func(
            syscallNumber,
            ThreadHandle,
            DesiredAccess,
            ObjectAttributes,
            ProcessHandle,
            StartRoutine,
            Argument,
            CreateFlags,
            ZeroBits,
            StackSize,
            MaximumStackSize,
            AttributeList
        );

        VirtualFree( mem, 0, MEM_RELEASE );

        return result;
#endif
    }

    static blackbone::ptr_t GetNtdll64Base()
    {
#ifdef _WIN64
        return 0;
#else
        if (!IsAvailable())
            return 0;

        BOOL isWow64 = FALSE;
        IsWow64Process( GetCurrentProcess(), &isWow64 );
        if (!isWow64)
            return 0;

        blackbone::ptr_t peb64 = 0;

        __asm {
            push eax
            mov eax, fs:[0x30]
            test eax, eax
            je not_wow64
            mov eax, [eax + 0x460]
            mov peb64, eax
            not_wow64 :
            pop eax
        }

        if (!peb64)
            return 0;

        return peb64;
#endif
    }

    static bool IsSyscallAvailable( DWORD syscallNumber )
    {
#ifdef _WIN64
        return false;
#else
        return IsAvailable();
#endif
    }
};
