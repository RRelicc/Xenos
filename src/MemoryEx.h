#pragma once

#include "Win11Compat.h"
#include "RetryHelper.h"
#include <BlackBone/Process/Process.h>
#include <vector>
#include <functional>

class MemoryEx
{
public:
    static blackbone::call_result_t<blackbone::ptr_t> AllocateOptimal(
        blackbone::Process& process,
        size_t size,
        DWORD protection = PAGE_EXECUTE_READWRITE,
        blackbone::ptr_t nearAddress = 0
        )
    {
        if (nearAddress == 0)
            nearAddress = GetPreferredBaseAddress( process );

        auto result = process.memory().Allocate( size, protection, nearAddress );

        if (!result.success() && nearAddress != 0)
        {
            result = process.memory().Allocate( size, protection );
        }

        return result;
    }

    static blackbone::ptr_t GetPreferredBaseAddress( blackbone::Process& process )
    {
        if (Win11Compat::IsWindows11OrGreater())
        {
            if (process.core().isWow64())
                return 0x0000000010000000;
            else
                return 0x0000000140000000;
        }

        return 0x0000000010000000;
    }

    static blackbone::call_result_t<blackbone::ptr_t> AllocateWithRetry(
        blackbone::Process& process,
        size_t size,
        DWORD protection = PAGE_EXECUTE_READWRITE,
        int maxRetries = 0
        )
    {
        if (maxRetries == 0)
            maxRetries = RetryHelper::GetRecommendedRetries();

        blackbone::ptr_t result = 0;
        NTSTATUS status = RetryHelper::Retry(
            [&]()
            {
                auto allocResult = AllocateOptimal( process, size, protection );
                if (allocResult.success())
                {
                    result = allocResult.result();
                    return STATUS_SUCCESS;
                }
                return STATUS_NO_MEMORY;
            },
            maxRetries,
            RetryHelper::GetRecommendedDelay()
        );

        return blackbone::call_result_t<blackbone::ptr_t>( result, status );
    }

    static NTSTATUS ProtectWithVerification(
        blackbone::Process& process,
        blackbone::ptr_t address,
        size_t size,
        DWORD newProtect,
        DWORD* oldProtect = nullptr
        )
    {
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        if (!VirtualQueryEx( process.core().handle(),
                           reinterpret_cast<LPCVOID>(address),
                           &mbi,
                           sizeof( mbi ) ))
        {
            return STATUS_INVALID_ADDRESS;
        }

        if (mbi.State != MEM_COMMIT)
            return STATUS_INVALID_ADDRESS;

        return process.memory().Protect( address, size, newProtect, oldProtect );
    }

    static std::vector<MEMORY_BASIC_INFORMATION> EnumerateRegions(
        blackbone::Process& process,
        DWORD stateFilter = MEM_COMMIT
        )
    {
        std::vector<MEMORY_BASIC_INFORMATION> regions;
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        blackbone::ptr_t address = 0;
        blackbone::ptr_t maxAddress = process.core().isWow64() ? 0x7FFF0000 : 0x7FFFFFFF0000;

        while (address < maxAddress &&
               VirtualQueryEx( process.core().handle(),
                             reinterpret_cast<LPCVOID>(address),
                             &mbi,
                             sizeof( mbi ) ))
        {
            if (mbi.State == stateFilter)
                regions.push_back( mbi );

            address += mbi.RegionSize;
        }

        return regions;
    }

    static std::vector<MEMORY_BASIC_INFORMATION> FindExecutableRegions( blackbone::Process& process )
    {
        std::vector<MEMORY_BASIC_INFORMATION> executableRegions;
        auto regions = EnumerateRegions( process );

        for (const auto& region : regions)
        {
            if (region.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                 PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
            {
                executableRegions.push_back( region );
            }
        }

        return executableRegions;
    }

    static blackbone::ptr_t FindCodeCave(
        blackbone::Process& process,
        size_t requiredSize,
        blackbone::ptr_t nearAddress = 0,
        blackbone::ptr_t searchRange = 0x7FFF0000
        )
    {
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        blackbone::ptr_t startAddress = nearAddress ? nearAddress : 0x10000;
        blackbone::ptr_t endAddress = startAddress + searchRange;

        if (endAddress > (process.core().isWow64() ? 0x7FFF0000 : 0x7FFFFFFF0000))
            endAddress = process.core().isWow64() ? 0x7FFF0000 : 0x7FFFFFFF0000;

        for (blackbone::ptr_t addr = startAddress; addr < endAddress; )
        {
            if (!VirtualQueryEx( process.core().handle(),
                               reinterpret_cast<LPCVOID>(addr),
                               &mbi,
                               sizeof( mbi ) ))
                break;

            if (mbi.State == MEM_FREE && mbi.RegionSize >= requiredSize)
                return addr;

            addr += mbi.RegionSize;
        }

        return 0;
    }

    static NTSTATUS WriteWithVerification(
        blackbone::Process& process,
        blackbone::ptr_t address,
        const void* data,
        size_t size
        )
    {
        DWORD oldProtect = 0;
        NTSTATUS status = ProtectWithVerification( process, address, size, PAGE_READWRITE, &oldProtect );

        if (!NT_SUCCESS( status ))
            return status;

        status = process.memory().Write( address, size, data );

        process.memory().Protect( address, size, oldProtect );
        return status;
    }

    static NTSTATUS ReadSafe(
        blackbone::Process& process,
        blackbone::ptr_t address,
        size_t size,
        void* buffer
        )
    {
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        if (!VirtualQueryEx( process.core().handle(),
                           reinterpret_cast<LPCVOID>(address),
                           &mbi,
                           sizeof( mbi ) ))
        {
            return STATUS_INVALID_ADDRESS;
        }

        if (mbi.State != MEM_COMMIT)
            return STATUS_INVALID_ADDRESS;

        if (mbi.RegionSize < size)
            return STATUS_BUFFER_OVERFLOW;

        return process.memory().Read( address, size, buffer );
    }

    static size_t GetTotalCommittedMemory( blackbone::Process& process )
    {
        auto regions = EnumerateRegions( process, MEM_COMMIT );
        size_t total = 0;

        for (const auto& region : regions)
            total += region.RegionSize;

        return total;
    }

    static size_t GetTotalExecutableMemory( blackbone::Process& process )
    {
        auto execRegions = FindExecutableRegions( process );
        size_t total = 0;

        for (const auto& region : execRegions)
            total += region.RegionSize;

        return total;
    }

    static blackbone::call_result_t<blackbone::ptr_t> AllocateNearModule(
        blackbone::Process& process,
        const std::wstring& moduleName,
        size_t size,
        DWORD protection = PAGE_EXECUTE_READWRITE
        )
    {
        auto mod = process.modules().GetModule( moduleName );
        if (!mod)
            return blackbone::call_result_t<blackbone::ptr_t>( 0, STATUS_NOT_FOUND );

        blackbone::ptr_t moduleBase = mod->baseAddress;

        for (blackbone::ptr_t offset = 0x10000; offset < 0x7FFF0000; offset += 0x10000)
        {
            auto result = process.memory().Allocate( size, protection, moduleBase + offset );
            if (result.success())
                return result;

            result = process.memory().Allocate( size, protection, moduleBase - offset );
            if (result.success())
                return result;
        }

        return blackbone::call_result_t<blackbone::ptr_t>( 0, STATUS_NO_MEMORY );
    }

    static std::vector<blackbone::ptr_t> ScanPattern(
        blackbone::Process& process,
        const std::vector<uint8_t>& pattern,
        const std::vector<bool>& mask,
        blackbone::ptr_t startAddress = 0,
        blackbone::ptr_t endAddress = 0
        )
    {
        std::vector<blackbone::ptr_t> results;

        if (endAddress == 0)
            endAddress = process.core().isWow64() ? 0x7FFF0000 : 0x7FFFFFFF0000;

        auto regions = EnumerateRegions( process, MEM_COMMIT );

        for (const auto& region : regions)
        {
            if (region.BaseAddress < startAddress ||
                reinterpret_cast<blackbone::ptr_t>(region.BaseAddress) > endAddress)
                continue;

            std::vector<uint8_t> buffer( region.RegionSize );
            if (NT_SUCCESS( process.memory().Read(
                reinterpret_cast<blackbone::ptr_t>(region.BaseAddress),
                region.RegionSize,
                buffer.data() ) ))
            {
                if (buffer.size() < pattern.size())
                    continue;

                for (size_t i = 0; i <= buffer.size() - pattern.size(); ++i)
                {
                    bool found = true;
                    for (size_t j = 0; j < pattern.size(); ++j)
                    {
                        if (mask[j] && buffer[i + j] != pattern[j])
                        {
                            found = false;
                            break;
                        }
                    }

                    if (found)
                        results.push_back( reinterpret_cast<blackbone::ptr_t>(region.BaseAddress) + i );
                }
            }
        }

        return results;
    }
};
