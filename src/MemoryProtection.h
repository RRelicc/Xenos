#pragma once

#include <Windows.h>
#include "Win11Compat.h"
#include <BlackBone/Process/Process.h>

class MemoryProtection
{
public:
    static bool ValidateExecutableRegion( blackbone::Process& process, uint64_t address, size_t size )
    {
        MEMORY_BASIC_INFORMATION mbi = { 0 };

        if (!VirtualQueryEx( process.core().handle(), reinterpret_cast<LPCVOID>(address), &mbi, sizeof( mbi ) ))
            return false;

        if (mbi.State != MEM_COMMIT)
            return false;

        if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
            return false;

        if (mbi.RegionSize < size)
            return false;

        return true;
    }

    static NTSTATUS SetMemoryExecutable( blackbone::Process& process, uint64_t address, size_t size )
    {
        DWORD oldProtect = 0;
        return process.memory().Protect( address, size, PAGE_EXECUTE_READWRITE, &oldProtect );
    }

    static NTSTATUS HideMemoryRegion( blackbone::Process& process, uint64_t address, size_t size )
    {
        return process.memory().Protect( address, size, PAGE_NOACCESS );
    }

    static bool IsAddressValid( blackbone::Process& process, uint64_t address )
    {
        MEMORY_BASIC_INFORMATION mbi = { 0 };

        if (!VirtualQueryEx( process.core().handle(), reinterpret_cast<LPCVOID>(address), &mbi, sizeof( mbi ) ))
            return false;

        return mbi.State == MEM_COMMIT;
    }

    static uint64_t FindCodeCave( blackbone::Process& process, size_t requiredSize, uint64_t nearAddress = 0 )
    {
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        uint64_t address = nearAddress ? nearAddress : 0x10000;

        while (VirtualQueryEx( process.core().handle(), reinterpret_cast<LPCVOID>(address), &mbi, sizeof( mbi ) ))
        {
            if (mbi.State == MEM_FREE && mbi.RegionSize >= requiredSize)
                return address;

            address += mbi.RegionSize;

            if (address >= 0x7FFFFFFF0000)
                break;
        }

        return 0;
    }

    static NTSTATUS AllocateNearby( blackbone::Process& process, uint64_t nearAddress, size_t size, uint64_t* outAddress )
    {
        const uint64_t range = 0x7FFF0000;

        for (uint64_t offset = 0x10000; offset < range; offset += 0x10000)
        {
            uint64_t tryAddr = nearAddress + offset;
            auto result = process.memory().Allocate( size, PAGE_EXECUTE_READWRITE, tryAddr );

            if (result.success())
            {
                *outAddress = result.result();
                return STATUS_SUCCESS;
            }

            tryAddr = nearAddress - offset;
            result = process.memory().Allocate( size, PAGE_EXECUTE_READWRITE, tryAddr );

            if (result.success())
            {
                *outAddress = result.result();
                return STATUS_SUCCESS;
            }
        }

        return STATUS_NO_MEMORY;
    }

    static std::vector<MEMORY_BASIC_INFORMATION> EnumerateMemory( blackbone::Process& process )
    {
        std::vector<MEMORY_BASIC_INFORMATION> regions;
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        uint64_t address = 0;

        while (VirtualQueryEx( process.core().handle(), reinterpret_cast<LPCVOID>(address), &mbi, sizeof( mbi ) ))
        {
            if (mbi.State == MEM_COMMIT)
                regions.push_back( mbi );

            address += mbi.RegionSize;

            if (address >= 0x7FFFFFFF0000)
                break;
        }

        return regions;
    }

    static size_t GetTotalCommittedMemory( blackbone::Process& process )
    {
        auto regions = EnumerateMemory( process );
        size_t total = 0;

        for (const auto& region : regions)
            total += region.RegionSize;

        return total;
    }

    static bool IsMemoryProtected( DWORD protect )
    {
        return (protect & PAGE_GUARD) || (protect & PAGE_NOACCESS);
    }

    static NTSTATUS ProtectMemoryRange( blackbone::Process& process, uint64_t address, size_t size, DWORD newProtect )
    {
        DWORD oldProtect = 0;
        return process.memory().Protect( address, size, newProtect, &oldProtect );
    }

    static bool CanAllocateInRange( blackbone::Process& process, uint64_t start, uint64_t end, size_t size )
    {
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        uint64_t address = start;

        while (address < end && VirtualQueryEx( process.core().handle(), reinterpret_cast<LPCVOID>(address), &mbi, sizeof( mbi ) ))
        {
            if (mbi.State == MEM_FREE && mbi.RegionSize >= size)
                return true;

            address += mbi.RegionSize;
        }

        return false;
    }

    static uint64_t GetPreferredAllocAddress( blackbone::Process& process )
    {
        if (Win11Compat::IsWindows11OrGreater())
            return 0x0000000140000000;

        return 0x0000000010000000;
    }
};
