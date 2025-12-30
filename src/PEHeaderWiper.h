#pragma once

#include "Win11Compat.h"
#include <BlackBone/Process/Process.h>
#include <BlackBone/PE/PEImage.h>

class PEHeaderWiper
{
public:
    struct WipeOptions
    {
        bool wipeDosHeader = true;
        bool wipeNtHeaders = true;
        bool wipeSectionHeaders = true;
        bool wipeImportDirectory = false;
        bool wipeExportDirectory = false;
        bool wipeRelocDirectory = false;
        bool wipeDebugDirectory = true;
        bool randomFill = false;
    };

    static NTSTATUS WipePEHeaders(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase,
        const WipeOptions& options = WipeOptions()
        )
    {
        blackbone::pe::PEImage img;
        std::vector<uint8_t> buffer;

        auto mod = process.modules().GetModule( moduleBase );
        if (!mod)
            return STATUS_NOT_FOUND;

        size_t headerSize = 0x1000;
        buffer.resize( headerSize );

        if (!NT_SUCCESS( process.memory().Read( moduleBase, headerSize, buffer.data() ) ))
            return STATUS_MEMORY_NOT_ALLOCATED;

        if (img.Parse( buffer.data(), buffer.size(), true ) != STATUS_SUCCESS)
            return STATUS_INVALID_IMAGE_FORMAT;

        DWORD oldProtect = 0;
        process.memory().Protect( moduleBase, headerSize, PAGE_READWRITE, &oldProtect );

        if (options.wipeDosHeader)
        {
            WipeDosHeader( process, moduleBase, options.randomFill );
        }

        if (options.wipeNtHeaders)
        {
            WipeNtHeaders( process, moduleBase, img, options.randomFill );
        }

        if (options.wipeSectionHeaders)
        {
            WipeSectionHeaders( process, moduleBase, img, options.randomFill );
        }

        if (options.wipeImportDirectory)
        {
            WipeDirectory( process, moduleBase, img, IMAGE_DIRECTORY_ENTRY_IMPORT, options.randomFill );
        }

        if (options.wipeExportDirectory)
        {
            WipeDirectory( process, moduleBase, img, IMAGE_DIRECTORY_ENTRY_EXPORT, options.randomFill );
        }

        if (options.wipeRelocDirectory)
        {
            WipeDirectory( process, moduleBase, img, IMAGE_DIRECTORY_ENTRY_BASERELOC, options.randomFill );
        }

        if (options.wipeDebugDirectory)
        {
            WipeDirectory( process, moduleBase, img, IMAGE_DIRECTORY_ENTRY_DEBUG, options.randomFill );
        }

        process.memory().Protect( moduleBase, headerSize, oldProtect, &oldProtect );

        return STATUS_SUCCESS;
    }

    static NTSTATUS WipeDosStub(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase,
        bool randomFill = false
        )
    {
        IMAGE_DOS_HEADER dosHeader = { 0 };
        if (!NT_SUCCESS( process.memory().Read( moduleBase, sizeof( dosHeader ), &dosHeader ) ))
            return STATUS_MEMORY_NOT_ALLOCATED;

        size_t stubSize = dosHeader.e_lfanew - sizeof( IMAGE_DOS_HEADER );
        if (stubSize > 0)
        {
            std::vector<uint8_t> zeros( stubSize, 0 );

            if (randomFill)
            {
                for (auto& b : zeros)
                    b = static_cast<uint8_t>(rand() % 256);
            }

            DWORD oldProtect = 0;
            process.memory().Protect( moduleBase + sizeof( IMAGE_DOS_HEADER ), stubSize, PAGE_READWRITE, &oldProtect );

            NTSTATUS status = process.memory().Write( moduleBase + sizeof( IMAGE_DOS_HEADER ), stubSize, zeros.data() );

            process.memory().Protect( moduleBase + sizeof( IMAGE_DOS_HEADER ), stubSize, oldProtect, &oldProtect );

            return status;
        }

        return STATUS_SUCCESS;
    }

    static NTSTATUS RestorePEHeaders(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase,
        const std::wstring& originalPath
        )
    {
        blackbone::pe::PEImage img;
        if (img.Load( originalPath ) != STATUS_SUCCESS)
            return STATUS_INVALID_IMAGE_FORMAT;

        std::vector<uint8_t> headerData;
        size_t headerSize = img.headersSize();

        headerData.resize( headerSize );

        if (!NT_SUCCESS( img.GetImage( headerData.data(), headerSize ) ))
            return STATUS_UNSUCCESSFUL;

        DWORD oldProtect = 0;
        process.memory().Protect( moduleBase, headerSize, PAGE_READWRITE, &oldProtect );

        NTSTATUS status = process.memory().Write( moduleBase, headerSize, headerData.data() );

        process.memory().Protect( moduleBase, headerSize, oldProtect, &oldProtect );

        return status;
    }

    static NTSTATUS WipeEntireHeaders(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase,
        bool randomFill = false
        )
    {
        blackbone::pe::PEImage img;
        std::vector<uint8_t> buffer;

        auto mod = process.modules().GetModule( moduleBase );
        if (!mod)
            return STATUS_NOT_FOUND;

        size_t headerSize = 0x1000;
        buffer.resize( headerSize );

        if (!NT_SUCCESS( process.memory().Read( moduleBase, headerSize, buffer.data() ) ))
            return STATUS_MEMORY_NOT_ALLOCATED;

        if (img.Parse( buffer.data(), buffer.size(), true ) != STATUS_SUCCESS)
            return STATUS_INVALID_IMAGE_FORMAT;

        size_t actualHeaderSize = img.headersSize();

        std::vector<uint8_t> zeros( actualHeaderSize, 0 );

        if (randomFill)
        {
            for (auto& b : zeros)
                b = static_cast<uint8_t>(rand() % 256);
        }

        DWORD oldProtect = 0;
        process.memory().Protect( moduleBase, actualHeaderSize, PAGE_READWRITE, &oldProtect );

        NTSTATUS status = process.memory().Write( moduleBase, actualHeaderSize, zeros.data() );

        process.memory().Protect( moduleBase, actualHeaderSize, oldProtect, &oldProtect );

        return status;
    }

    static bool IsHeaderWiped(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase
        )
    {
        IMAGE_DOS_HEADER dosHeader = { 0 };
        if (!NT_SUCCESS( process.memory().Read( moduleBase, sizeof( dosHeader ), &dosHeader ) ))
            return false;

        return dosHeader.e_magic != IMAGE_DOS_SIGNATURE;
    }

private:
    static void WipeDosHeader(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase,
        bool randomFill
        )
    {
        IMAGE_DOS_HEADER dosHeader = { 0 };
        process.memory().Read( moduleBase, sizeof( dosHeader ), &dosHeader );

        uint32_t e_lfanew = dosHeader.e_lfanew;

        if (randomFill)
        {
            for (size_t i = 0; i < sizeof( IMAGE_DOS_HEADER ); i++)
                reinterpret_cast<uint8_t*>(&dosHeader)[i] = static_cast<uint8_t>(rand() % 256);
        }
        else
        {
            memset( &dosHeader, 0, sizeof( dosHeader ) );
        }

        dosHeader.e_lfanew = e_lfanew;

        process.memory().Write( moduleBase, sizeof( dosHeader ), &dosHeader );
    }

    static void WipeNtHeaders(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase,
        blackbone::pe::PEImage& img,
        bool randomFill
        )
    {
        IMAGE_DOS_HEADER dosHeader = { 0 };
        process.memory().Read( moduleBase, sizeof( dosHeader ), &dosHeader );

        if (img.mType() == blackbone::mt_mod64)
        {
            IMAGE_NT_HEADERS64 ntHeaders = { 0 };
            size_t size = sizeof( ntHeaders );

            if (randomFill)
            {
                for (size_t i = 0; i < size; i++)
                    reinterpret_cast<uint8_t*>(&ntHeaders)[i] = static_cast<uint8_t>(rand() % 256);
            }

            process.memory().Write( moduleBase + dosHeader.e_lfanew, size, &ntHeaders );
        }
        else
        {
            IMAGE_NT_HEADERS32 ntHeaders = { 0 };
            size_t size = sizeof( ntHeaders );

            if (randomFill)
            {
                for (size_t i = 0; i < size; i++)
                    reinterpret_cast<uint8_t*>(&ntHeaders)[i] = static_cast<uint8_t>(rand() % 256);
            }

            process.memory().Write( moduleBase + dosHeader.e_lfanew, size, &ntHeaders );
        }
    }

    static void WipeSectionHeaders(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase,
        blackbone::pe::PEImage& img,
        bool randomFill
        )
    {
        auto sections = img.sections();

        IMAGE_DOS_HEADER dosHeader = { 0 };
        process.memory().Read( moduleBase, sizeof( dosHeader ), &dosHeader );

        size_t ntHeaderSize = (img.mType() == blackbone::mt_mod64) ? sizeof( IMAGE_NT_HEADERS64 ) : sizeof( IMAGE_NT_HEADERS32 );

        blackbone::ptr_t sectionHeadersStart = moduleBase + dosHeader.e_lfanew + ntHeaderSize;
        size_t sectionHeadersSize = sections.size() * sizeof( IMAGE_SECTION_HEADER );

        std::vector<uint8_t> zeros( sectionHeadersSize, 0 );

        if (randomFill)
        {
            for (auto& b : zeros)
                b = static_cast<uint8_t>(rand() % 256);
        }

        process.memory().Write( sectionHeadersStart, sectionHeadersSize, zeros.data() );
    }

    static void WipeDirectory(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase,
        blackbone::pe::PEImage& img,
        DWORD directoryEntry,
        bool randomFill
        )
    {
        auto dir = img.DirectoryAddress( directoryEntry );
        if (!dir)
            return;

        size_t dirSize = img.DirectorySize( directoryEntry );
        if (dirSize == 0)
            return;

        std::vector<uint8_t> zeros( dirSize, 0 );

        if (randomFill)
        {
            for (auto& b : zeros)
                b = static_cast<uint8_t>(rand() % 256);
        }

        process.memory().Write( moduleBase + dir, dirSize, zeros.data() );
    }
};
