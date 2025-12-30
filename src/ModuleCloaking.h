#pragma once

#include <Windows.h>
#include "Win11Compat.h"
#include <BlackBone/Process/Process.h>

class ModuleCloaking
{
public:
    static NTSTATUS UnlinkFromPEB( blackbone::Process& process, uint64_t moduleBase )
    {
        bool isWow64 = process.core().isWow64();

        if (isWow64)
            return UnlinkFromPEB32( process, moduleBase );
        else
            return UnlinkFromPEB64( process, moduleBase );
    }

    static NTSTATUS HideMemoryFromVAD( blackbone::Process& process, uint64_t address, size_t size )
    {
        auto& driver = blackbone::Driver();

        NTSTATUS status = driver.EnsureLoaded();
        if (!NT_SUCCESS( status ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        return driver.ConcealVAD( process.pid(), address, static_cast<uint32_t>(size) );
    }

    static NTSTATUS ErasePEHeader( blackbone::Process& process, uint64_t moduleBase )
    {
        IMAGE_DOS_HEADER dosHeader = { 0 };
        NTSTATUS status = process.memory().Read( moduleBase, sizeof( dosHeader ), &dosHeader );

        if (!NT_SUCCESS( status ) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
            return STATUS_INVALID_IMAGE_FORMAT;

        IMAGE_NT_HEADERS64 ntHeaders = { 0 };
        status = process.memory().Read( moduleBase + dosHeader.e_lfanew, sizeof( ntHeaders ), &ntHeaders );

        if (!NT_SUCCESS( status ))
            return status;

        size_t headerSize = ntHeaders.OptionalHeader.SizeOfHeaders;
        std::vector<uint8_t> zeros( headerSize, 0 );

        return process.memory().Write( moduleBase, headerSize, zeros.data() );
    }

    static NTSTATUS RandomizeSectionNames( blackbone::Process& process, uint64_t moduleBase )
    {
        IMAGE_DOS_HEADER dosHeader = { 0 };
        NTSTATUS status = process.memory().Read( moduleBase, sizeof( dosHeader ), &dosHeader );

        if (!NT_SUCCESS( status ))
            return status;

        IMAGE_NT_HEADERS64 ntHeaders = { 0 };
        status = process.memory().Read( moduleBase + dosHeader.e_lfanew, sizeof( ntHeaders ), &ntHeaders );

        if (!NT_SUCCESS( status ))
            return status;

        blackbone::ptr_t sectionHeaderAddr = moduleBase + dosHeader.e_lfanew + sizeof( DWORD ) + sizeof( IMAGE_FILE_HEADER ) + ntHeaders.FileHeader.SizeOfOptionalHeader;

        for (WORD i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
        {
            IMAGE_SECTION_HEADER section = { 0 };
            status = process.memory().Read( sectionHeaderAddr + i * sizeof( section ), sizeof( section ), &section );

            if (!NT_SUCCESS( status ))
                continue;

            for (int j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++)
                section.Name[j] = 'A' + (rand() % 26);

            process.memory().Write( sectionHeaderAddr + i * sizeof( section ), sizeof( section ), &section );
        }

        return STATUS_SUCCESS;
    }

private:
    static NTSTATUS UnlinkFromPEB32( blackbone::Process& process, uint64_t moduleBase )
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    static NTSTATUS UnlinkFromPEB64( blackbone::Process& process, uint64_t moduleBase )
    {
        blackbone::_PEB64 peb = { 0 };
        auto pebAddr = process.core().peb64( &peb );

        if (!pebAddr)
            return STATUS_UNSUCCESSFUL;

        return STATUS_SUCCESS;
    }

public:
    static bool IsCloakingRequired()
    {
        return Win11Compat::IsWindows11OrGreater() ||
               Win11Compat::RequiresEnhancedEvasion();
    }

    static NTSTATUS ApplyFullCloaking( blackbone::Process& process, uint64_t moduleBase )
    {
        NTSTATUS status = ErasePEHeader( process, moduleBase );
        if (!NT_SUCCESS( status ))
            return status;

        status = UnlinkFromPEB( process, moduleBase );
        if (!NT_SUCCESS( status ))
            return status;

        status = RandomizeSectionNames( process, moduleBase );
        if (!NT_SUCCESS( status ))
            return status;

        if (Win11Compat::SupportsKernelInjection())
        {
            status = HideMemoryFromVAD( process, moduleBase, 0x1000 );
        }

        return status;
    }
};
