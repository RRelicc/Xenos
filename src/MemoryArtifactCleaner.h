#pragma once

#include "Win11Compat.h"
#include <BlackBone/Process/Process.h>
#include <BlackBone/PE/PEImage.h>
#include <vector>

class MemoryArtifactCleaner
{
public:
    struct CleanupOptions
    {
        bool cleanLoaderData = true;
        bool cleanTemporaryAllocations = true;
        bool cleanThreadStacks = false;
        bool cleanEnvironmentStrings = false;
        bool cleanModulePaths = true;
        bool randomFillFreedMemory = false;
    };

    static NTSTATUS CleanInjectionArtifacts(
        blackbone::Process& process,
        blackbone::ptr_t injectedModuleBase,
        const CleanupOptions& options = CleanupOptions()
        )
    {
        if (options.cleanLoaderData)
        {
            CleanLoaderData( process, injectedModuleBase );
        }

        if (options.cleanTemporaryAllocations)
        {
            CleanTemporaryAllocations( process );
        }

        if (options.cleanThreadStacks)
        {
            CleanThreadStackArtifacts( process );
        }

        if (options.cleanModulePaths)
        {
            CleanModulePaths( process, injectedModuleBase );
        }

        return STATUS_SUCCESS;
    }

    static NTSTATUS CleanAllocationPatterns(
        blackbone::Process& process,
        blackbone::ptr_t baseAddress,
        size_t size
        )
    {
        std::vector<uint8_t> randomData( size );

        for (auto& b : randomData)
            b = static_cast<uint8_t>(rand() % 256);

        DWORD oldProtect = 0;
        process.memory().Protect( baseAddress, size, PAGE_READWRITE, &oldProtect );

        NTSTATUS status = process.memory().Write( baseAddress, size, randomData.data() );

        process.memory().Protect( baseAddress, size, oldProtect, &oldProtect );

        return status;
    }

    static NTSTATUS WipeUnusedMemoryRegions(
        blackbone::Process& process,
        bool randomFill = false
        )
    {
        std::vector<blackbone::MEMORY_BASIC_INFORMATION64> regions;

        blackbone::ptr_t address = 0;
        blackbone::MEMORY_BASIC_INFORMATION64 mbi = { 0 };

        while (NT_SUCCESS( process.memory().Query( address, &mbi ) ))
        {
            if (mbi.State == MEM_FREE && mbi.RegionSize > 0x1000 && mbi.RegionSize < 0x100000)
            {
                regions.push_back( mbi );
            }

            address = mbi.BaseAddress + mbi.RegionSize;
        }

        for (const auto& region : regions)
        {
            auto mem = process.memory().Allocate( region.RegionSize, PAGE_READWRITE, region.BaseAddress );
            if (mem)
            {
                std::vector<uint8_t> data( static_cast<size_t>(region.RegionSize), 0 );

                if (randomFill)
                {
                    for (auto& b : data)
                        b = static_cast<uint8_t>(rand() % 256);
                }

                process.memory().Write( mem->ptr(), data.size(), data.data() );
                process.memory().Free( mem->ptr() );
            }
        }

        return STATUS_SUCCESS;
    }

    static NTSTATUS CleanCodeCaves(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase
        )
    {
        blackbone::pe::PEImage img;
        std::vector<uint8_t> buffer;

        auto mod = process.modules().GetModule( moduleBase );
        if (!mod)
            return STATUS_NOT_FOUND;

        if (!NT_SUCCESS( process.memory().Read( moduleBase, mod->size, buffer ) ))
            return STATUS_MEMORY_NOT_ALLOCATED;

        if (img.Parse( buffer.data(), buffer.size(), true ) != STATUS_SUCCESS)
            return STATUS_INVALID_IMAGE_FORMAT;

        auto sections = img.sections();

        for (const auto& section : sections)
        {
            if (!(section.Characteristics & IMAGE_SCN_CNT_CODE))
                continue;

            blackbone::ptr_t sectionStart = moduleBase + section.VirtualAddress;
            size_t sectionSize = section.Misc.VirtualSize;

            std::vector<uint8_t> sectionData( sectionSize );
            if (!NT_SUCCESS( process.memory().Read( sectionStart, sectionSize, sectionData.data() ) ))
                continue;

            size_t nullCount = 0;
            size_t nullStart = 0;

            for (size_t i = 0; i < sectionSize; i++)
            {
                if (sectionData[i] == 0x00 || sectionData[i] == 0xCC)
                {
                    if (nullCount == 0)
                        nullStart = i;
                    nullCount++;
                }
                else
                {
                    if (nullCount >= 16)
                    {
                        std::vector<uint8_t> nops( nullCount, 0x90 );

                        DWORD oldProtect = 0;
                        process.memory().Protect( sectionStart + nullStart, nullCount, PAGE_READWRITE, &oldProtect );

                        process.memory().Write( sectionStart + nullStart, nullCount, nops.data() );

                        process.memory().Protect( sectionStart + nullStart, nullCount, oldProtect, &oldProtect );
                    }

                    nullCount = 0;
                }
            }
        }

        return STATUS_SUCCESS;
    }

    static NTSTATUS OverwriteStrings(
        blackbone::Process& process,
        blackbone::ptr_t baseAddress,
        size_t size,
        const std::vector<std::string>& patterns
        )
    {
        std::vector<uint8_t> buffer( size );

        if (!NT_SUCCESS( process.memory().Read( baseAddress, size, buffer.data() ) ))
            return STATUS_MEMORY_NOT_ALLOCATED;

        for (const auto& pattern : patterns)
        {
            for (size_t i = 0; i < size - pattern.size(); i++)
            {
                if (memcmp( buffer.data() + i, pattern.c_str(), pattern.size() ) == 0)
                {
                    for (size_t j = 0; j < pattern.size(); j++)
                        buffer[i + j] = static_cast<uint8_t>(rand() % 26 + 'a');
                }
            }
        }

        DWORD oldProtect = 0;
        process.memory().Protect( baseAddress, size, PAGE_READWRITE, &oldProtect );

        NTSTATUS status = process.memory().Write( baseAddress, size, buffer.data() );

        process.memory().Protect( baseAddress, size, oldProtect, &oldProtect );

        return status;
    }

    static NTSTATUS WipeFreedMemory(
        blackbone::Process& process
        )
    {
        std::vector<blackbone::ptr_t> freedRegions;

        blackbone::ptr_t address = 0;
        blackbone::MEMORY_BASIC_INFORMATION64 mbi = { 0 };

        while (NT_SUCCESS( process.memory().Query( address, &mbi ) ))
        {
            if (mbi.State == MEM_FREE && mbi.RegionSize > 0)
            {
                freedRegions.push_back( mbi.BaseAddress );
            }

            address = mbi.BaseAddress + mbi.RegionSize;

            if (address < mbi.BaseAddress)
                break;
        }

        return STATUS_SUCCESS;
    }

private:
    static void CleanLoaderData(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase
        )
    {
        auto mod = process.modules().GetModule( moduleBase );
        if (!mod)
            return;

        std::wstring emptyPath = L"";
        size_t pathSize = emptyPath.size() * sizeof( wchar_t );

        blackbone::ptr_t baseNamePtr = reinterpret_cast<blackbone::ptr_t>(mod->baseName.c_str());
        blackbone::ptr_t fullPathPtr = reinterpret_cast<blackbone::ptr_t>(mod->fullPath.c_str());

        if (baseNamePtr)
        {
            std::vector<wchar_t> zeros( 260, 0 );
            process.memory().Write( baseNamePtr, zeros.size() * sizeof( wchar_t ), zeros.data() );
        }

        if (fullPathPtr)
        {
            std::vector<wchar_t> zeros( 260, 0 );
            process.memory().Write( fullPathPtr, zeros.size() * sizeof( wchar_t ), zeros.data() );
        }
    }

    static void CleanTemporaryAllocations(
        blackbone::Process& process
        )
    {
        blackbone::ptr_t address = 0;
        blackbone::MEMORY_BASIC_INFORMATION64 mbi = { 0 };

        while (NT_SUCCESS( process.memory().Query( address, &mbi ) ))
        {
            if (mbi.State == MEM_COMMIT &&
                mbi.Type == MEM_PRIVATE &&
                mbi.RegionSize < 0x10000 &&
                mbi.Protect == PAGE_READWRITE)
            {
                std::vector<uint8_t> data;
                data.resize( static_cast<size_t>(mbi.RegionSize) );

                if (NT_SUCCESS( process.memory().Read( mbi.BaseAddress, data.size(), data.data() ) ))
                {
                    bool isLikelyTemporary = true;

                    for (size_t i = 0; i < data.size() && i < 0x100; i++)
                    {
                        if (data[i] != 0)
                        {
                            isLikelyTemporary = false;
                            break;
                        }
                    }

                    if (isLikelyTemporary)
                    {
                        process.memory().Free( mbi.BaseAddress );
                    }
                }
            }

            address = mbi.BaseAddress + mbi.RegionSize;

            if (address < mbi.BaseAddress)
                break;
        }
    }

    static void CleanThreadStackArtifacts(
        blackbone::Process& process
        )
    {
        auto& threads = process.threads().getAll();

        for (auto& thread : threads)
        {
            blackbone::ptr_t teb = thread->teb();
            if (!teb)
                continue;

            blackbone::ptr_t stackBase = 0;
            blackbone::ptr_t stackLimit = 0;

            if (process.core().isWow64())
            {
                process.memory().Read( teb + 4, sizeof( uint32_t ), &stackBase );
                process.memory().Read( teb + 8, sizeof( uint32_t ), &stackLimit );
            }
            else
            {
                process.memory().Read( teb + 8, sizeof( blackbone::ptr_t ), &stackBase );
                process.memory().Read( teb + 16, sizeof( blackbone::ptr_t ), &stackLimit );
            }

            if (stackBase && stackLimit && stackBase > stackLimit)
            {
                size_t stackSize = static_cast<size_t>(stackBase - stackLimit);
                if (stackSize > 0x100000)
                    continue;

                std::vector<uint8_t> stackData( stackSize );
                if (NT_SUCCESS( process.memory().Read( stackLimit, stackSize, stackData.data() ) ))
                {
                    for (size_t i = 0; i < stackSize - sizeof( blackbone::ptr_t ); i++)
                    {
                        blackbone::ptr_t* ptrVal = reinterpret_cast<blackbone::ptr_t*>(&stackData[i]);

                        if (*ptrVal >= 0x10000 && *ptrVal < 0x7FFFFFFF0000)
                        {
                            *ptrVal = 0;
                        }
                    }

                    DWORD oldProtect = 0;
                    process.memory().Protect( stackLimit, stackSize, PAGE_READWRITE, &oldProtect );

                    process.memory().Write( stackLimit, stackSize, stackData.data() );

                    process.memory().Protect( stackLimit, stackSize, oldProtect, &oldProtect );
                }
            }
        }
    }

    static void CleanModulePaths(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase
        )
    {
        auto mod = process.modules().GetModule( moduleBase );
        if (!mod)
            return;

        std::wstring modulePath = mod->fullPath;

        size_t searchSize = 0x100000;
        blackbone::ptr_t searchStart = 0x10000;

        blackbone::MEMORY_BASIC_INFORMATION64 mbi = { 0 };

        while (NT_SUCCESS( process.memory().Query( searchStart, &mbi ) ))
        {
            if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE)
            {
                std::vector<uint8_t> data;
                data.resize( static_cast<size_t>(mbi.RegionSize) );

                if (NT_SUCCESS( process.memory().Read( mbi.BaseAddress, data.size(), data.data() ) ))
                {
                    for (size_t i = 0; i < data.size() - modulePath.size() * sizeof( wchar_t ); i++)
                    {
                        if (memcmp( data.data() + i, modulePath.c_str(), modulePath.size() * sizeof( wchar_t ) ) == 0)
                        {
                            std::vector<wchar_t> zeros( modulePath.size(), 0 );
                            process.memory().Write( mbi.BaseAddress + i, zeros.size() * sizeof( wchar_t ), zeros.data() );
                        }
                    }
                }
            }

            searchStart = mbi.BaseAddress + mbi.RegionSize;

            if (searchStart < mbi.BaseAddress)
                break;
        }
    }
};
