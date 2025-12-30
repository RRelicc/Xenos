#pragma once

#include "Win11Compat.h"
#include <BlackBone/Symbols/SymbolLoader.h>
#include <BlackBone/PE/PEImage.h>
#include <string>
#include <map>

class SymbolEx
{
public:
    struct SymbolInfo
    {
        std::string name;
        blackbone::ptr_t address = 0;
        size_t size = 0;
        bool valid = false;
    };

    static NTSTATUS LoadSymbols( const std::wstring& modulePath, std::map<std::string, blackbone::ptr_t>& symbols )
    {
        blackbone::pe::PEImage img;
        NTSTATUS status = img.Load( modulePath );
        if (!NT_SUCCESS( status ))
            return status;

        blackbone::pe::vecExports exports;
        img.GetExports( exports );

        for (const auto& exp : exports)
        {
            symbols[exp.name] = exp.address;
        }

        return STATUS_SUCCESS;
    }

    static blackbone::ptr_t ResolveSymbol(
        const std::wstring& modulePath,
        const std::string& symbolName
        )
    {
        blackbone::pe::PEImage img;
        if (img.Load( modulePath ) != STATUS_SUCCESS)
            return 0;

        blackbone::pe::vecExports exports;
        img.GetExports( exports );

        for (const auto& exp : exports)
        {
            if (exp.name == symbolName)
                return exp.address;
        }

        return 0;
    }

    static std::vector<std::string> EnumerateExports( const std::wstring& modulePath )
    {
        std::vector<std::string> exportNames;

        blackbone::pe::PEImage img;
        if (img.Load( modulePath ) != STATUS_SUCCESS)
            return exportNames;

        blackbone::pe::vecExports exports;
        img.GetExports( exports );

        for (const auto& exp : exports)
        {
            exportNames.push_back( exp.name );
        }

        return exportNames;
    }

    static std::vector<std::wstring> EnumerateImports( const std::wstring& modulePath )
    {
        std::vector<std::wstring> importNames;

        blackbone::pe::PEImage img;
        if (img.Load( modulePath ) != STATUS_SUCCESS)
            return importNames;

        auto& imports = img.GetImports();

        for (const auto& dll : imports)
        {
            importNames.push_back( dll.first );
        }

        return importNames;
    }

    static bool HasExport( const std::wstring& modulePath, const std::string& exportName )
    {
        blackbone::pe::PEImage img;
        if (img.Load( modulePath ) != STATUS_SUCCESS)
            return false;

        blackbone::pe::vecExports exports;
        img.GetExports( exports );

        for (const auto& exp : exports)
        {
            if (exp.name == exportName)
                return true;
        }

        return false;
    }

    static bool HasImport( const std::wstring& modulePath, const std::wstring& dllName )
    {
        blackbone::pe::PEImage img;
        if (img.Load( modulePath ) != STATUS_SUCCESS)
            return false;

        auto& imports = img.GetImports();
        return imports.find( dllName ) != imports.end();
    }

    static size_t GetExportCount( const std::wstring& modulePath )
    {
        blackbone::pe::PEImage img;
        if (img.Load( modulePath ) != STATUS_SUCCESS)
            return 0;

        blackbone::pe::vecExports exports;
        img.GetExports( exports );

        return exports.size();
    }

    static size_t GetImportCount( const std::wstring& modulePath )
    {
        blackbone::pe::PEImage img;
        if (img.Load( modulePath ) != STATUS_SUCCESS)
            return 0;

        return img.GetImports().size();
    }

    static std::vector<SymbolInfo> GetDetailedExports( const std::wstring& modulePath )
    {
        std::vector<SymbolInfo> symbols;

        blackbone::pe::PEImage img;
        if (img.Load( modulePath ) != STATUS_SUCCESS)
            return symbols;

        blackbone::pe::vecExports exports;
        img.GetExports( exports );

        for (const auto& exp : exports)
        {
            SymbolInfo info;
            info.name = exp.name;
            info.address = exp.address;
            info.size = 0;
            info.valid = true;
            symbols.push_back( info );
        }

        return symbols;
    }

    static blackbone::ptr_t FindExportByOrdinal( const std::wstring& modulePath, WORD ordinal )
    {
        blackbone::pe::PEImage img;
        if (img.Load( modulePath ) != STATUS_SUCCESS)
            return 0;

        blackbone::pe::vecExports exports;
        img.GetExports( exports );

        for (const auto& exp : exports)
        {
            if (exp.ordinal == ordinal)
                return exp.address;
        }

        return 0;
    }

    static std::map<std::string, blackbone::ptr_t> GetAllExports( const std::wstring& modulePath )
    {
        std::map<std::string, blackbone::ptr_t> exportMap;

        blackbone::pe::PEImage img;
        if (img.Load( modulePath ) != STATUS_SUCCESS)
            return exportMap;

        blackbone::pe::vecExports exports;
        img.GetExports( exports );

        for (const auto& exp : exports)
        {
            exportMap[exp.name] = exp.address;
        }

        return exportMap;
    }

    static std::vector<std::string> FindExportsByPattern( const std::wstring& modulePath, const std::string& pattern )
    {
        std::vector<std::string> matches;

        blackbone::pe::PEImage img;
        if (img.Load( modulePath ) != STATUS_SUCCESS)
            return matches;

        blackbone::pe::vecExports exports;
        img.GetExports( exports );

        for (const auto& exp : exports)
        {
            if (exp.name.find( pattern ) != std::string::npos)
                matches.push_back( exp.name );
        }

        return matches;
    }
};
