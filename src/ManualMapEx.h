#pragma once

#include "Win11Compat.h"
#include "PEValidator.h"
#include "MemoryEx.h"
#include "RetryHelper.h"
#include <BlackBone/ManualMap/MMap.h>
#include <BlackBone/Process/Process.h>

class ManualMapEx
{
public:
    struct MapConfig
    {
        bool eraseHeaders = true;
        bool hideVAD = true;
        bool unlinkVAD = false;
        bool noTLS = false;
        bool noExceptions = false;
        bool partialExceptions = false;
        bool noDelayLoad = false;
        bool noSxS = false;
        bool initRoutine = true;
        bool manualImports = true;
        bool rebaseProcess = true;
        int mapFlags = 0;
    };

    static MapConfig GetOptimalConfig( blackbone::Process& process )
    {
        MapConfig config;

        if (Win11Compat::IsWindows11OrGreater())
        {
            config.eraseHeaders = true;
            config.hideVAD = true;
            config.unlinkVAD = true;
            config.noExceptions = false;
            config.partialExceptions = true;
        }

        if (Win11Compat::IsHVCIEnabled())
        {
            config.eraseHeaders = true;
            config.unlinkVAD = true;
        }

        if (Win11Compat::IsCFGEnabled( process.core().handle() ))
        {
            config.eraseHeaders = false;
            config.noExceptions = false;
        }

        return config;
    }

    static int BuildMapFlags( const MapConfig& config )
    {
        int flags = 0;

        if (config.manualImports)
            flags |= blackbone::ManualImports;
        if (config.rebaseProcess)
            flags |= blackbone::RebaseProcess;
        if (config.noTLS)
            flags |= blackbone::NoTLS;
        if (config.noExceptions)
            flags |= blackbone::NoExceptions;
        if (config.partialExceptions)
            flags |= blackbone::PartialExcept;
        if (config.noDelayLoad)
            flags |= blackbone::NoDelayLoad;
        if (config.noSxS)
            flags |= blackbone::NoSxS;
        if (config.eraseHeaders)
            flags |= blackbone::WipeHeader;
        if (config.hideVAD)
            flags |= blackbone::HideVAD;
        if (config.unlinkVAD)
            flags |= blackbone::UnlinkVAD;

        return flags;
    }

    static NTSTATUS MapImageSafe(
        blackbone::Process& process,
        const std::wstring& imagePath,
        const MapConfig& config,
        blackbone::ptr_t& imageBase
        )
    {
        int flags = BuildMapFlags( config );

        auto result = process.mmap().MapImage( imagePath, flags );
        if (result.success())
            imageBase = result.result();

        return result.status;
    }

    static NTSTATUS UnmapImage( blackbone::Process& process, blackbone::ptr_t imageBase )
    {
        return process.mmap().UnmapAllModules();
    }

    static bool IsImageMapped( blackbone::Process& process, const std::wstring& imageName )
    {
        auto modules = process.modules().GetAllModules();

        for (const auto& mod : modules)
        {
            if (mod.second->name.find( imageName ) != std::wstring::npos)
                return true;
        }

        return false;
    }

    static NTSTATUS MapWithCallback(
        blackbone::Process& process,
        const std::wstring& imagePath,
        const MapConfig& config,
        blackbone::ptr_t& imageBase,
        std::function<void( const std::wstring& )> callback
        )
    {
        if (callback)
            callback( L"Preparing image..." );

        blackbone::pe::PEImage img;
        NTSTATUS status = img.Load( imagePath );
        if (!NT_SUCCESS( status ))
            return status;

        if (callback)
            callback( L"Mapping image..." );

        int flags = BuildMapFlags( config );
        auto result = process.mmap().MapImage( imagePath, flags );

        if (result.success())
        {
            imageBase = result.result();
            if (callback)
                callback( L"Image mapped successfully" );
        }
        else
        {
            if (callback)
                callback( L"Mapping failed" );
        }

        return result.status;
    }

    static NTSTATUS InjectWithRetry(
        blackbone::Process& process,
        const std::wstring& imagePath,
        const MapConfig& config,
        blackbone::ptr_t& imageBase,
        int maxRetries = 0
        )
    {
        if (maxRetries == 0)
            maxRetries = RetryHelper::GetRecommendedRetries();

        return RetryHelper::Retry(
            [&]() { return MapImageSafe( process, imagePath, config, imageBase ); },
            maxRetries,
            RetryHelper::GetRecommendedDelay(),
            RetryHelper::IsRetryableStatus
        );
    }

    static std::vector<std::wstring> GetMappedImages( blackbone::Process& process )
    {
        std::vector<std::wstring> mappedImages;
        auto modules = process.modules().GetAllModules();

        for (const auto& mod : modules)
        {
            mappedImages.push_back( mod.second->fullPath );
        }

        return mappedImages;
    }

    static size_t GetTotalMappedSize( blackbone::Process& process )
    {
        size_t totalSize = 0;
        auto modules = process.modules().GetAllModules();

        for (const auto& mod : modules)
        {
            totalSize += mod.second->size;
        }

        return totalSize;
    }

    static NTSTATUS MapMultipleImages(
        blackbone::Process& process,
        const std::vector<std::wstring>& imagePaths,
        const MapConfig& config
        )
    {
        for (const auto& imagePath : imagePaths)
        {
            blackbone::ptr_t imageBase = 0;
            NTSTATUS status = MapImageSafe( process, imagePath, config, imageBase );

            if (!NT_SUCCESS( status ))
                return status;
        }

        return STATUS_SUCCESS;
    }

    static bool ValidateMapping( blackbone::Process& process, blackbone::ptr_t imageBase )
    {
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        if (!VirtualQueryEx( process.core().handle(),
                           reinterpret_cast<LPCVOID>(imageBase),
                           &mbi,
                           sizeof( mbi ) ))
        {
            return false;
        }

        return mbi.State == MEM_COMMIT;
    }
};
