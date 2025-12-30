#pragma once

#include <Windows.h>
#include "Win11Compat.h"
#include <BlackBone/Process/Process.h>
#include <BlackBone/PE/PEImage.h>
#include <BlackBone/Patterns/PatternSearch.h>

class ReflectiveLoader
{
public:
    static NTSTATUS InjectReflective(
        blackbone::Process& process,
        const std::wstring& dllPath,
        const std::string& loaderFunction = "ReflectiveLoader",
        uint64_t* outModule = nullptr
        )
    {
        blackbone::pe::PEImage image;
        NTSTATUS status = image.Load( dllPath, true );

        if (!NT_SUCCESS( status ))
            return status;

        blackbone::pe::vecExports exports;
        image.GetExports( exports );

        uint32_t loaderRVA = 0;
        for (const auto& exp : exports)
        {
            if (exp.name == loaderFunction)
            {
                loaderRVA = exp.RVA;
                break;
            }
        }

        if (loaderRVA == 0)
            return STATUS_PROCEDURE_NOT_FOUND;

        auto imageSize = image.imageSize();
        void* imageData = image.base();

        auto allocResult = process.memory().Allocate( imageSize, PAGE_EXECUTE_READWRITE );
        if (!allocResult.success())
            return allocResult.status;

        ptr_t remoteBase = allocResult.result();

        status = process.memory().Write( remoteBase, imageSize, imageData );
        if (!NT_SUCCESS( status ))
        {
            process.memory().Free( remoteBase );
            return status;
        }

        auto threadResult = process.threads().CreateNew(
            remoteBase + loaderRVA,
            remoteBase,
            blackbone::CreateSuspended
            );

        if (!threadResult.success())
        {
            process.memory().Free( remoteBase );
            return threadResult.status;
        }

        auto thread = threadResult.result();
        thread->Resume();
        thread->Join( INFINITE );

        DWORD exitCode = thread->ExitCode();

        if (outModule)
            *outModule = exitCode;

        image.Release();
        return STATUS_SUCCESS;
    }

    static NTSTATUS InjectReflectiveSRDI(
        blackbone::Process& process,
        const std::wstring& dllPath,
        const std::string& exportFunction = "",
        const std::string& userData = "",
        uint64_t* outResult = nullptr
        )
    {
        blackbone::pe::PEImage image;
        NTSTATUS status = image.Load( dllPath, true );

        if (!NT_SUCCESS( status ))
            return status;

        std::vector<uint8_t> shellcode = GenerateSRDIShellcode( image, exportFunction, userData );

        if (shellcode.empty())
            return STATUS_INVALID_IMAGE_FORMAT;

        auto allocResult = process.memory().Allocate( shellcode.size(), PAGE_EXECUTE_READWRITE );
        if (!allocResult.success())
            return allocResult.status;

        ptr_t remoteShellcode = allocResult.result();

        status = process.memory().Write( remoteShellcode, shellcode.size(), shellcode.data() );
        if (!NT_SUCCESS( status ))
        {
            process.memory().Free( remoteShellcode );
            return status;
        }

        auto threadResult = process.threads().CreateNew(
            remoteShellcode,
            0,
            blackbone::CreateSuspended
            );

        if (!threadResult.success())
        {
            process.memory().Free( remoteShellcode );
            return threadResult.status;
        }

        auto thread = threadResult.result();
        thread->Resume();
        thread->Join( INFINITE );

        DWORD exitCode = thread->ExitCode();

        if (outResult)
            *outResult = exitCode;

        process.memory().Free( remoteShellcode );
        image.Release();

        return STATUS_SUCCESS;
    }

private:
    static std::vector<uint8_t> GenerateSRDIShellcode(
        blackbone::pe::PEImage& image,
        const std::string& exportFunction,
        const std::string& userData
        )
    {
        std::vector<uint8_t> shellcode;

        void* imageData = image.base();
        auto imageSize = image.imageSize();

        shellcode.resize( imageSize + 4096 );

        size_t offset = 0;

        uint8_t loaderStub[] = {
            0x55,
            0x48, 0x89, 0xE5,
            0x48, 0x83, 0xEC, 0x20,
            0x48, 0x89, 0xCB,
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0x5E,
            0x48, 0x81, 0xC6, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x89, 0xD9,
            0xFF, 0xD6,
            0x48, 0x83, 0xC4, 0x20,
            0x5D,
            0xC3
        };

        memcpy( shellcode.data(), loaderStub, sizeof( loaderStub ) );
        offset += sizeof( loaderStub );

        memcpy( shellcode.data() + offset, imageData, imageSize );
        offset += imageSize;

        return shellcode;
    }

public:
    static bool IsReflectiveLoaderPresent( blackbone::pe::PEImage& image )
    {
        blackbone::pe::vecExports exports;
        image.GetExports( exports );

        for (const auto& exp : exports)
        {
            if (exp.name.find( "Reflective" ) != std::string::npos ||
                exp.name.find( "ReflectiveLoader" ) != std::string::npos)
            {
                return true;
            }
        }

        return false;
    }

    static NTSTATUS InjectWithMemoryProtection(
        blackbone::Process& process,
        const std::wstring& dllPath,
        bool eraseHeaders = true,
        uint64_t* outModule = nullptr
        )
    {
        uint64_t moduleBase = 0;
        NTSTATUS status = InjectReflective( process, dllPath, "ReflectiveLoader", &moduleBase );

        if (!NT_SUCCESS( status ))
            return status;

        if (eraseHeaders && moduleBase != 0)
        {
            std::vector<uint8_t> zeros( 4096, 0 );
            process.memory().Write( moduleBase, 4096, zeros.data() );
        }

        if (outModule)
            *outModule = moduleBase;

        return status;
    }

    static bool RequiresReflectiveLoading()
    {
        return Win11Compat::IsWindows11OrGreater() ||
               Win11Compat::IsHVCIEnabled() ||
               Win11Compat::RequiresEnhancedEvasion();
    }
};
