#pragma once

#include "Win11Compat.h"
#include "PathValidator.h"
#include "PEValidator.h"
#include <BlackBone/Process/Process.h>
#include <BlackBone/PE/PEImage.h>
#include <vector>
#include <string>
#include <optional>

class ModuleEx
{
public:
    static blackbone::ModuleDataPtr GetModuleSafe(
        blackbone::Process& process,
        const std::wstring& moduleName
        )
    {
        auto mod = process.modules().GetModule( moduleName );
        if (!mod)
        {
            process.modules().Refresh();
            mod = process.modules().GetModule( moduleName );
        }

        return mod;
    }

    static std::vector<blackbone::ModuleDataPtr> GetAllModules( blackbone::Process& process )
    {
        std::vector<blackbone::ModuleDataPtr> modules;

        process.modules().Refresh();

        for (auto& mod : process.modules().GetAllModules())
            modules.emplace_back( mod.second );

        return modules;
    }

    static std::vector<blackbone::ModuleDataPtr> FindModulesByName(
        blackbone::Process& process,
        const std::wstring& namePattern
        )
    {
        std::vector<blackbone::ModuleDataPtr> matches;
        auto allModules = GetAllModules( process );

        for (auto& mod : allModules)
        {
            if (mod->name.find( namePattern ) != std::wstring::npos)
                matches.emplace_back( mod );
        }

        return matches;
    }

    static blackbone::ModuleDataPtr GetMainModule( blackbone::Process& process )
    {
        return process.modules().GetMainModule();
    }

    static blackbone::ptr_t GetProcAddressSafe(
        blackbone::Process& process,
        const std::wstring& moduleName,
        const char* functionName
        )
    {
        auto mod = GetModuleSafe( process, moduleName );
        if (!mod)
            return 0;

        auto exportData = mod->GetExport( functionName );
        if (!exportData)
            return 0;

        return exportData->procAddress;
    }

    static blackbone::ptr_t GetProcAddressByOrdinal(
        blackbone::Process& process,
        const std::wstring& moduleName,
        WORD ordinal
        )
    {
        auto mod = GetModuleSafe( process, moduleName );
        if (!mod)
            return 0;

        blackbone::pe::PEImage img;
        if (img.Load( mod->fullPath ) != STATUS_SUCCESS)
            return 0;

        blackbone::pe::vecExports exports;
        img.GetExports( exports );

        for (const auto& exp : exports)
        {
            if (exp.ordinal == ordinal)
            {
                auto exportData = mod->GetExport( exp.name );
                if (exportData)
                    return exportData->procAddress;
            }
        }

        return 0;
    }

    static std::vector<std::string> GetExportedFunctions(
        blackbone::Process& process,
        const std::wstring& moduleName
        )
    {
        std::vector<std::string> functions;
        auto mod = GetModuleSafe( process, moduleName );
        if (!mod)
            return functions;

        blackbone::pe::PEImage img;
        if (img.Load( mod->fullPath ) != STATUS_SUCCESS)
            return functions;

        blackbone::pe::vecExports exports;
        img.GetExports( exports );

        for (const auto& exp : exports)
            functions.push_back( exp.name );

        return functions;
    }

    static std::vector<std::wstring> GetImportedModules(
        blackbone::Process& process,
        const std::wstring& moduleName
        )
    {
        std::vector<std::wstring> imports;
        auto mod = GetModuleSafe( process, moduleName );
        if (!mod)
            return imports;

        blackbone::pe::PEImage img;
        if (img.Load( mod->fullPath ) != STATUS_SUCCESS)
            return imports;

        auto& importMap = img.GetImports();
        for (const auto& dll : importMap)
            imports.push_back( dll.first );

        return imports;
    }

    static bool IsModuleLoaded(
        blackbone::Process& process,
        const std::wstring& moduleName
        )
    {
        return GetModuleSafe( process, moduleName ) != nullptr;
    }

    static NTSTATUS UnloadModule(
        blackbone::Process& process,
        const std::wstring& moduleName
        )
    {
        auto mod = GetModuleSafe( process, moduleName );
        if (!mod)
            return STATUS_NOT_FOUND;

        return process.modules().Unload( mod );
    }

    static size_t GetModuleSize(
        blackbone::Process& process,
        const std::wstring& moduleName
        )
    {
        auto mod = GetModuleSafe( process, moduleName );
        if (!mod)
            return 0;

        return mod->size;
    }

    static std::wstring GetModulePath(
        blackbone::Process& process,
        const std::wstring& moduleName
        )
    {
        auto mod = GetModuleSafe( process, moduleName );
        if (!mod)
            return L"";

        return mod->fullPath;
    }

    static blackbone::ptr_t GetModuleBase(
        blackbone::Process& process,
        const std::wstring& moduleName
        )
    {
        auto mod = GetModuleSafe( process, moduleName );
        if (!mod)
            return 0;

        return mod->baseAddress;
    }

    static bool IsModule64Bit( const std::wstring& modulePath )
    {
        blackbone::pe::PEImage img;
        if (img.Load( modulePath ) != STATUS_SUCCESS)
            return false;

        return img.mType() == blackbone::mt_mod64;
    }

    static bool IsModuleSigned( const std::wstring& modulePath )
    {
        WINTRUST_FILE_INFO fileInfo = { 0 };
        fileInfo.cbStruct = sizeof( fileInfo );
        fileInfo.pcwszFilePath = modulePath.c_str();

        WINTRUST_DATA trustData = { 0 };
        trustData.cbStruct = sizeof( trustData );
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;

        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG status = WinVerifyTrust( nullptr, &policyGUID, &trustData );

        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust( nullptr, &policyGUID, &trustData );

        return status == ERROR_SUCCESS;
    }

    static PEValidator::ValidationResult ValidateModule( const std::wstring& modulePath )
    {
        blackbone::pe::PEImage img;
        if (img.Load( modulePath ) != STATUS_SUCCESS)
        {
            PEValidator::ValidationResult result;
            result.AddError( L"Failed to load PE image" );
            return result;
        }

        return PEValidator::Validate( img );
    }

    static bool IsCompatibleWithProcess(
        blackbone::Process& process,
        const std::wstring& modulePath
        )
    {
        blackbone::pe::PEImage img;
        if (img.Load( modulePath ) != STATUS_SUCCESS)
            return false;

        bool targetWow64 = process.core().isWow64();
        return PEValidator::IsCompatibleWithTarget( img, targetWow64 );
    }

    static std::vector<blackbone::ModuleDataPtr> GetModulesByProtection(
        blackbone::Process& process,
        DWORD protectionMask
        )
    {
        std::vector<blackbone::ModuleDataPtr> matches;
        auto allModules = GetAllModules( process );

        for (auto& mod : allModules)
        {
            MEMORY_BASIC_INFORMATION mbi = { 0 };
            if (VirtualQueryEx( process.core().handle(),
                              reinterpret_cast<LPCVOID>(mod->baseAddress),
                              &mbi,
                              sizeof( mbi ) ))
            {
                if (mbi.Protect & protectionMask)
                    matches.push_back( mod );
            }
        }

        return matches;
    }

    static size_t GetTotalModulesSize( blackbone::Process& process )
    {
        auto modules = GetAllModules( process );
        size_t total = 0;

        for (auto& mod : modules)
            total += mod->size;

        return total;
    }
};
