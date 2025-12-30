#pragma once

#include "Win11Compat.h"
#include "PEValidator.h"
#include <BlackBone/PE/PEImage.h>
#include <string>
#include <vector>

class PEEx
{
public:
    struct SectionInfo
    {
        std::string name;
        blackbone::ptr_t virtualAddress = 0;
        size_t virtualSize = 0;
        size_t rawSize = 0;
        DWORD characteristics = 0;
        bool executable = false;
        bool writable = false;
        bool readable = false;
    };

    struct PEInfo
    {
        bool is64Bit = false;
        bool isDLL = false;
        bool isNET = false;
        blackbone::ptr_t entryPoint = 0;
        blackbone::ptr_t imageBase = 0;
        size_t imageSize = 0;
        WORD subsystem = 0;
        std::vector<SectionInfo> sections;
    };

    static NTSTATUS LoadPE( const std::wstring& path, blackbone::pe::PEImage& image )
    {
        return image.Load( path );
    }

    static PEInfo GetPEInfo( const std::wstring& path )
    {
        PEInfo info;

        blackbone::pe::PEImage img;
        if (img.Load( path ) != STATUS_SUCCESS)
            return info;

        info.is64Bit = (img.mType() == blackbone::mt_mod64);
        info.isDLL = (img.peType() == blackbone::pe::PEType::dll);
        info.isNET = img.IsPureIL();
        info.entryPoint = img.entryPoint();
        info.imageBase = img.imageBase();
        info.imageSize = img.imageSize();
        info.subsystem = img.subsystem();

        auto sections = img.sections();
        for (const auto& sec : sections)
        {
            SectionInfo sectionInfo;
            sectionInfo.name = std::string( reinterpret_cast<const char*>(sec.Name), 8 );
            sectionInfo.virtualAddress = sec.VirtualAddress;
            sectionInfo.virtualSize = sec.Misc.VirtualSize;
            sectionInfo.rawSize = sec.SizeOfRawData;
            sectionInfo.characteristics = sec.Characteristics;
            sectionInfo.executable = (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            sectionInfo.writable = (sec.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            sectionInfo.readable = (sec.Characteristics & IMAGE_SCN_MEM_READ) != 0;

            info.sections.push_back( sectionInfo );
        }

        return info;
    }

    static std::vector<SectionInfo> GetSections( const std::wstring& path )
    {
        return GetPEInfo( path ).sections;
    }

    static SectionInfo FindSection( const std::wstring& path, const std::string& sectionName )
    {
        auto sections = GetSections( path );

        for (const auto& section : sections)
        {
            if (section.name == sectionName)
                return section;
        }

        return SectionInfo();
    }

    static std::vector<SectionInfo> FindExecutableSections( const std::wstring& path )
    {
        std::vector<SectionInfo> execSections;
        auto sections = GetSections( path );

        for (const auto& section : sections)
        {
            if (section.executable)
                execSections.push_back( section );
        }

        return execSections;
    }

    static bool Is64Bit( const std::wstring& path )
    {
        blackbone::pe::PEImage img;
        if (img.Load( path ) != STATUS_SUCCESS)
            return false;

        return img.mType() == blackbone::mt_mod64;
    }

    static bool IsDLL( const std::wstring& path )
    {
        blackbone::pe::PEImage img;
        if (img.Load( path ) != STATUS_SUCCESS)
            return false;

        return img.peType() == blackbone::pe::PEType::dll;
    }

    static bool IsNET( const std::wstring& path )
    {
        blackbone::pe::PEImage img;
        if (img.Load( path ) != STATUS_SUCCESS)
            return false;

        return img.IsPureIL();
    }

    static blackbone::ptr_t GetEntryPoint( const std::wstring& path )
    {
        blackbone::pe::PEImage img;
        if (img.Load( path ) != STATUS_SUCCESS)
            return 0;

        return img.entryPoint();
    }

    static size_t GetImageSize( const std::wstring& path )
    {
        blackbone::pe::PEImage img;
        if (img.Load( path ) != STATUS_SUCCESS)
            return 0;

        return img.imageSize();
    }

    static blackbone::ptr_t GetImageBase( const std::wstring& path )
    {
        blackbone::pe::PEImage img;
        if (img.Load( path ) != STATUS_SUCCESS)
            return 0;

        return img.imageBase();
    }

    static WORD GetSubsystem( const std::wstring& path )
    {
        blackbone::pe::PEImage img;
        if (img.Load( path ) != STATUS_SUCCESS)
            return 0;

        return img.subsystem();
    }

    static bool HasRelocations( const std::wstring& path )
    {
        blackbone::pe::PEImage img;
        if (img.Load( path ) != STATUS_SUCCESS)
            return false;

        return !img.noReloc();
    }

    static bool HasTLS( const std::wstring& path )
    {
        blackbone::pe::PEImage img;
        if (img.Load( path ) != STATUS_SUCCESS)
            return false;

        return img.HasTLS();
    }

    static bool HasExceptions( const std::wstring& path )
    {
        blackbone::pe::PEImage img;
        if (img.Load( path ) != STATUS_SUCCESS)
            return false;

        return img.HasExceptions();
    }

    static PEValidator::ValidationResult ValidatePE( const std::wstring& path )
    {
        blackbone::pe::PEImage img;
        if (img.Load( path ) != STATUS_SUCCESS)
        {
            PEValidator::ValidationResult result;
            result.AddError( L"Failed to load PE" );
            return result;
        }

        return PEValidator::Validate( img );
    }

    static size_t GetSectionCount( const std::wstring& path )
    {
        return GetSections( path ).size();
    }

    static size_t GetCodeSize( const std::wstring& path )
    {
        size_t codeSize = 0;
        auto sections = GetSections( path );

        for (const auto& section : sections)
        {
            if (section.executable)
                codeSize += section.virtualSize;
        }

        return codeSize;
    }
};
