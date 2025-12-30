#pragma once

#include "Win11Compat.h"
#include "ProcessEx.h"
#include "MemoryEx.h"
#include "ModuleEx.h"
#include "PEValidator.h"
#include "PathValidator.h"
#include "RetryHelper.h"
#include <BlackBone/Process/Process.h>
#include <BlackBone/ManualMap/MMap.h>

class InjectionEx
{
public:
    enum InjectionMethod
    {
        LoadLibrary,
        ManualMap,
        ThreadHijack,
        KernelAPC,
        KernelManualMap
    };

    struct InjectionConfig
    {
        InjectionMethod method = LoadLibrary;
        bool eraseHeaders = false;
        bool hideModule = false;
        bool initRoutine = true;
        bool unlink = false;
        int retryCount = 3;
        DWORD retryDelay = 100;
        bool validatePE = true;
        bool checkCompatibility = true;
    };

    static InjectionConfig GetOptimalConfig( blackbone::Process& process )
    {
        InjectionConfig config;

        if (Win11Compat::IsWindows11OrGreater())
        {
            config.method = ManualMap;
            config.eraseHeaders = true;
            config.hideModule = true;
            config.unlink = true;
            config.retryCount = 5;
            config.retryDelay = 200;
        }
        else if (Win11Compat::RequiresEnhancedEvasion())
        {
            config.method = ManualMap;
            config.eraseHeaders = true;
            config.hideModule = true;
            config.retryCount = 4;
        }
        else
        {
            config.method = LoadLibrary;
            config.retryCount = 3;
            config.retryDelay = 100;
        }

        if (Win11Compat::IsHVCIEnabled())
        {
            config.method = ManualMap;
            config.eraseHeaders = true;
        }

        if (Win11Compat::IsCFGEnabled( process.core().handle() ))
        {
            config.eraseHeaders = false;
            config.method = ManualMap;
        }

        return config;
    }

    static NTSTATUS InjectDLL(
        blackbone::Process& process,
        const std::wstring& dllPath,
        const InjectionConfig& config = InjectionConfig()
        )
    {
        if (!PathValidator::FileExists( dllPath ))
            return STATUS_NOT_FOUND;

        if (!PathValidator::HasValidImageExtension( dllPath ))
            return STATUS_INVALID_IMAGE_FORMAT;

        if (config.validatePE)
        {
            auto validation = ModuleEx::ValidateModule( dllPath );
            if (!validation.valid)
                return STATUS_INVALID_IMAGE_FORMAT;
        }

        if (config.checkCompatibility)
        {
            if (!ModuleEx::IsCompatibleWithProcess( process, dllPath ))
                return STATUS_INVALID_IMAGE_FORMAT;
        }

        return RetryHelper::Retry(
            [&]() { return InjectDLLInternal( process, dllPath, config ); },
            config.retryCount,
            config.retryDelay,
            RetryHelper::IsRetryableStatus
        );
    }

    static NTSTATUS InjectMultipleDLLs(
        blackbone::Process& process,
        const std::vector<std::wstring>& dllPaths,
        const InjectionConfig& config = InjectionConfig()
        )
    {
        for (const auto& dllPath : dllPaths)
        {
            NTSTATUS status = InjectDLL( process, dllPath, config );
            if (!NT_SUCCESS( status ))
                return status;
        }

        return STATUS_SUCCESS;
    }

    static bool IsInjected( blackbone::Process& process, const std::wstring& dllPath )
    {
        std::wstring dllName = PathValidator::GetFileName( dllPath );
        return ModuleEx::IsModuleLoaded( process, dllName );
    }

    static NTSTATUS EjectDLL( blackbone::Process& process, const std::wstring& moduleName )
    {
        if (!ModuleEx::IsModuleLoaded( process, moduleName ))
            return STATUS_NOT_FOUND;

        return ModuleEx::UnloadModule( process, moduleName );
    }

    static std::vector<std::wstring> GetInjectedDLLs( blackbone::Process& process )
    {
        std::vector<std::wstring> injectedDLLs;
        auto modules = ModuleEx::GetAllModules( process );

        for (auto& mod : modules)
        {
            if (!IsSystemModule( mod->fullPath ))
                injectedDLLs.push_back( mod->fullPath );
        }

        return injectedDLLs;
    }

    static NTSTATUS ValidateInjection(
        blackbone::Process& process,
        const std::wstring& moduleName
        )
    {
        if (!ModuleEx::IsModuleLoaded( process, moduleName ))
            return STATUS_NOT_FOUND;

        auto mod = ModuleEx::GetModuleSafe( process, moduleName );
        if (!mod)
            return STATUS_NOT_FOUND;

        MEMORY_BASIC_INFORMATION mbi = { 0 };
        if (!VirtualQueryEx( process.core().handle(),
                           reinterpret_cast<LPCVOID>(mod->baseAddress),
                           &mbi,
                           sizeof( mbi ) ))
        {
            return STATUS_INVALID_ADDRESS;
        }

        if (mbi.State != MEM_COMMIT)
            return STATUS_INVALID_ADDRESS;

        return STATUS_SUCCESS;
    }

private:
    static NTSTATUS InjectDLLInternal(
        blackbone::Process& process,
        const std::wstring& dllPath,
        const InjectionConfig& config
        )
    {
        switch (config.method)
        {
        case LoadLibrary:
            return InjectViaLoadLibrary( process, dllPath );
        case ManualMap:
            return InjectViaManualMap( process, dllPath, config );
        default:
            return STATUS_NOT_IMPLEMENTED;
        }
    }

    static NTSTATUS InjectViaLoadLibrary( blackbone::Process& process, const std::wstring& dllPath )
    {
        auto kernelMod = process.modules().GetModule( L"kernel32.dll" );
        if (!kernelMod)
            kernelMod = process.modules().GetModule( L"kernelbase.dll" );

        if (!kernelMod)
            return STATUS_NOT_FOUND;

        auto loadLibrary = kernelMod->GetExport( "LoadLibraryW" );
        if (!loadLibrary)
            return STATUS_NOT_FOUND;

        auto pathMem = process.memory().Allocate( (dllPath.length() + 1) * sizeof( wchar_t ), PAGE_READWRITE );
        if (!pathMem.success())
            return pathMem.status;

        process.memory().Write( pathMem.result(), (dllPath.length() + 1) * sizeof( wchar_t ), dllPath.c_str() );

        uint64_t result = 0;
        NTSTATUS status = process.remote().ExecInNewThread(
            reinterpret_cast<PVOID>(loadLibrary->procAddress),
            0,
            result
        );

        process.memory().Free( pathMem.result() );

        return status;
    }

    static NTSTATUS InjectViaManualMap(
        blackbone::Process& process,
        const std::wstring& dllPath,
        const InjectionConfig& config
        )
    {
        blackbone::pe::PEImage img;
        NTSTATUS status = img.Load( dllPath );
        if (!NT_SUCCESS( status ))
            return status;

        int flags = 0;
        if (!config.initRoutine)
            flags |= blackbone::NoTLS;
        if (config.eraseHeaders)
            flags |= blackbone::WipeHeader;
        if (config.unlink)
            flags |= blackbone::UnlinkVAD;
        if (config.hideModule)
            flags |= blackbone::HideVAD;

        auto result = process.mmap().MapImage(
            dllPath,
            blackbone::ManualImports | blackbone::RebaseProcess | flags
        );

        return result.status;
    }

    static bool IsSystemModule( const std::wstring& modulePath )
    {
        wchar_t systemDir[MAX_PATH] = { 0 };
        GetSystemDirectoryW( systemDir, MAX_PATH );

        wchar_t windowsDir[MAX_PATH] = { 0 };
        GetWindowsDirectoryW( windowsDir, MAX_PATH );

        std::wstring pathLower = modulePath;
        std::transform( pathLower.begin(), pathLower.end(), pathLower.begin(), ::towlower );

        std::wstring sysDirLower = systemDir;
        std::transform( sysDirLower.begin(), sysDirLower.end(), sysDirLower.begin(), ::towlower );

        std::wstring winDirLower = windowsDir;
        std::transform( winDirLower.begin(), winDirLower.end(), winDirLower.begin(), ::towlower );

        return pathLower.find( sysDirLower ) == 0 || pathLower.find( winDirLower ) == 0;
    }
};
