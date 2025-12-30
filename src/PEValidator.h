#pragma once

#include <BlackBone/PE/PEImage.h>
#include <string>
#include <vector>
#include "Win11Compat.h"

class PEValidator
{
public:
    enum ValidationFlags
    {
        None = 0,
        CheckSignature = 1 << 0,
        CheckSections = 1 << 1,
        CheckImports = 1 << 2,
        CheckRelocations = 1 << 3,
        CheckExports = 1 << 4,
        All = CheckSignature | CheckSections | CheckImports | CheckRelocations | CheckExports
    };

    struct ValidationResult
    {
        bool valid = true;
        std::vector<std::wstring> warnings;
        std::vector<std::wstring> errors;

        void AddWarning( const std::wstring& msg )
        {
            warnings.push_back( msg );
        }

        void AddError( const std::wstring& msg )
        {
            errors.push_back( msg );
            valid = false;
        }

        bool HasIssues() const
        {
            return !warnings.empty() || !errors.empty();
        }
    };

    static ValidationResult Validate( blackbone::pe::PEImage& img, int flags = All )
    {
        ValidationResult result;

        if (flags & CheckSignature)
            ValidateSignature( img, result );

        if (flags & CheckSections)
            ValidateSections( img, result );

        if (flags & CheckImports)
            ValidateImports( img, result );

        if (flags & CheckRelocations)
            ValidateRelocations( img, result );

        if (flags & CheckExports)
            ValidateExports( img, result );

        return result;
    }

private:
    static void ValidateSignature( blackbone::pe::PEImage& img, ValidationResult& result )
    {
        if (img.pureIL())
            result.AddWarning( L"Pure IL image detected - may have limited compatibility" );
    }

    static void ValidateSections( blackbone::pe::PEImage& img, ValidationResult& result )
    {
        auto& sections = img.sections();

        if (sections.empty())
        {
            result.AddError( L"No sections found in PE image" );
            return;
        }

        for (const auto& section : sections)
        {
            if (section.Characteristics == 0)
                result.AddWarning( L"Section '" + blackbone::Utils::AnsiToWstring( reinterpret_cast<const char*>(section.Name) ) + L"' has no characteristics" );

            if (section.VirtualAddress == 0 && section.SizeOfRawData > 0)
                result.AddWarning( L"Section '" + blackbone::Utils::AnsiToWstring( reinterpret_cast<const char*>(section.Name) ) + L"' has zero virtual address" );
        }
    }

    static void ValidateImports( blackbone::pe::PEImage& img, ValidationResult& result )
    {
        if (img.pureIL())
            return;

        auto& imports = img.GetImports();

        if (imports.empty())
            result.AddWarning( L"No imports found - image may not be injectable" );

        for (const auto& dll : imports)
        {
            if (dll.second.empty())
                result.AddWarning( L"DLL '" + dll.first + L"' has no imported functions" );
        }
    }

    static void ValidateRelocations( blackbone::pe::PEImage& img, ValidationResult& result )
    {
        if (img.pureIL())
            return;

        if (img.mType() == blackbone::mt_mod64)
        {
            auto relocAddr = img.DirectoryAddress( IMAGE_DIRECTORY_ENTRY_BASERELOC );
            if (relocAddr == 0)
                result.AddWarning( L"No relocations found in 64-bit image - manual mapping may fail" );
        }
    }

    static void ValidateExports( blackbone::pe::PEImage& img, ValidationResult& result )
    {
        blackbone::pe::vecExports exports;
        img.GetExports( exports );

        if (!exports.empty())
        {
            for (const auto& exp : exports)
            {
                if (exp.name.empty())
                    result.AddWarning( L"Export with empty name" );
            }
        }
    }

public:
    static bool IsCompatibleWithTarget( blackbone::pe::PEImage& img, bool targetWow64 )
    {
        if (img.pureIL())
            return true;

        if (img.mType() == blackbone::mt_mod32 && !targetWow64)
            return false;

        if (img.mType() == blackbone::mt_mod64 && targetWow64)
            return false;

        return true;
    }

    static bool RequiresManualMap( blackbone::pe::PEImage& img )
    {
        if (Win11Compat::RequiresEnhancedEvasion())
            return true;

        auto relocAddr = img.DirectoryAddress( IMAGE_DIRECTORY_ENTRY_BASERELOC );
        return relocAddr == 0;
    }

    static bool IsDotNetAssembly( blackbone::pe::PEImage& img )
    {
        return img.pureIL() || img.DirectoryAddress( IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR ) != 0;
    }

    static size_t GetImageCodeSize( blackbone::pe::PEImage& img )
    {
        size_t totalSize = 0;
        auto& sections = img.sections();

        for (const auto& section : sections)
        {
            if (section.Characteristics & IMAGE_SCN_CNT_CODE)
                totalSize += section.Misc.VirtualSize;
        }

        return totalSize;
    }

    static bool HasDebugInfo( blackbone::pe::PEImage& img )
    {
        return img.DirectoryAddress( IMAGE_DIRECTORY_ENTRY_DEBUG ) != 0;
    }

    static std::wstring GetImageCharacteristics( blackbone::pe::PEImage& img )
    {
        std::wstring chars;

        if (img.pureIL())
            chars += L"Pure IL, ";

        if (img.mType() == blackbone::mt_mod32)
            chars += L"x86, ";
        else if (img.mType() == blackbone::mt_mod64)
            chars += L"x64, ";

        if (HasDebugInfo( img ))
            chars += L"Debug Info, ";

        if (!chars.empty())
            chars = chars.substr( 0, chars.length() - 2 );

        return chars;
    }
};
