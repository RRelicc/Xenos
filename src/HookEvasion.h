#pragma once

#include <Windows.h>
#include <vector>
#include "Win11Compat.h"
#include <BlackBone/Process/Process.h>
#include <BlackBone/Patterns/PatternSearch.h>

using namespace blackbone;

class HookEvasion
{
public:
    enum EvasionMethod
    {
        DirectSyscall,
        FreshCopy,
        UnhookNtdll,
        SyscallStub
    };

    static NTSTATUS UnhookModule( blackbone::Process& process, const std::wstring& moduleName )
    {
        auto mod = process.modules().GetModule( moduleName );

        if (!mod)
            return STATUS_NOT_FOUND;

        blackbone::pe::PEImage freshImage;
        NTSTATUS status = freshImage.Load( mod->fullPath, true );

        if (!NT_SUCCESS( status ))
            return status;

        const auto& sections = freshImage.sections();
        const IMAGE_SECTION_HEADER* textSection = nullptr;

        for (const auto& section : sections)
        {
            if (memcmp( section.Name, ".text", 5 ) == 0)
            {
                textSection = &section;
                break;
            }
        }

        if (!textSection)
            return STATUS_INVALID_IMAGE_FORMAT;

        ptr_t textVA = mod->baseAddress + textSection->VirtualAddress;
        uint32_t textSize = textSection->Misc.VirtualSize;

        uint8_t* freshText = reinterpret_cast<uint8_t*>(freshImage.base()) + textSection->VirtualAddress;

        DWORD oldProtect = 0;
        status = process.memory().Protect( textVA, textSize, PAGE_EXECUTE_READWRITE, &oldProtect );

        if (!NT_SUCCESS( status ))
            return status;

        status = process.memory().Write( textVA, textSize, freshText );

        process.memory().Protect( textVA, textSize, oldProtect );

        freshImage.Release();
        return status;
    }

    static NTSTATUS GetSyscallNumber( const std::string& functionName, WORD* outSyscallNumber )
    {
        auto ntdll = GetModuleHandleW( L"ntdll.dll" );
        if (!ntdll)
            return STATUS_DLL_NOT_FOUND;

        auto funcAddr = reinterpret_cast<uint8_t*>( GetProcAddress( ntdll, functionName.c_str() ) );
        if (!funcAddr)
            return STATUS_PROCEDURE_NOT_FOUND;

#ifdef _WIN64
        if (funcAddr[0] == 0x4C && funcAddr[1] == 0x8B && funcAddr[2] == 0xD1 &&
            funcAddr[3] == 0xB8)
        {
            *outSyscallNumber = *reinterpret_cast<WORD*>( funcAddr + 4 );
            return STATUS_SUCCESS;
        }
#else
        if (funcAddr[0] == 0xB8)
        {
            *outSyscallNumber = *reinterpret_cast<WORD*>( funcAddr + 1 );
            return STATUS_SUCCESS;
        }
#endif

        return STATUS_INVALID_IMAGE_FORMAT;
    }

    static std::vector<uint8_t> GenerateSyscallStub( WORD syscallNumber )
    {
#ifdef _WIN64
        std::vector<uint8_t> stub = {
            0x4C, 0x8B, 0xD1,
            0xB8, static_cast<uint8_t>(syscallNumber & 0xFF), static_cast<uint8_t>((syscallNumber >> 8) & 0xFF), 0x00, 0x00,
            0x0F, 0x05,
            0xC3
        };
#else
        std::vector<uint8_t> stub = {
            0xB8, static_cast<uint8_t>(syscallNumber & 0xFF), static_cast<uint8_t>((syscallNumber >> 8) & 0xFF), 0x00, 0x00,
            0xBA, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xD2,
            0xC2, 0x00, 0x00
        };
#endif
        return stub;
    }

    static NTSTATUS InjectWithEvasion(
        blackbone::Process& process,
        const std::wstring& dllPath,
        EvasionMethod method = UnhookNtdll
        )
    {
        NTSTATUS status = STATUS_SUCCESS;

        switch (method)
        {
            case UnhookNtdll:
                status = UnhookModule( process, L"ntdll.dll" );
                if (!NT_SUCCESS( status ))
                    return status;
                break;

            case FreshCopy:
                status = InjectFreshCopy( process, dllPath );
                return status;

            case DirectSyscall:
                status = InjectViaSyscall( process, dllPath );
                return status;

            default:
                break;
        }

        auto result = process.mmap().MapImage( dllPath );
        return result.success() ? STATUS_SUCCESS : result.status;
    }

private:
    static NTSTATUS InjectFreshCopy( blackbone::Process& process, const std::wstring& dllPath )
    {
        wchar_t tempPath[MAX_PATH] = { 0 };
        wchar_t tempFile[MAX_PATH] = { 0 };

        GetTempPathW( MAX_PATH, tempPath );
        GetTempFileNameW( tempPath, L"tmp", 0, tempFile );

        if (!CopyFileW( dllPath.c_str(), tempFile, FALSE ))
            return STATUS_UNSUCCESSFUL;

        auto result = process.mmap().MapImage( tempFile );
        DeleteFileW( tempFile );

        return result.success() ? STATUS_SUCCESS : result.status;
    }

    static NTSTATUS InjectViaSyscall( blackbone::Process& process, const std::wstring& dllPath )
    {
        WORD syscallNum = 0;
        NTSTATUS status = GetSyscallNumber( "NtCreateThreadEx", &syscallNum );

        if (!NT_SUCCESS( status ))
            return status;

        auto stub = GenerateSyscallStub( syscallNum );

        auto result = process.mmap().MapImage( dllPath );
        return result.success() ? STATUS_SUCCESS : result.status;
    }

public:
    static EvasionMethod GetRecommendedMethod()
    {
        if (Win11Compat::IsWindows11OrGreater())
        {
            if (Win11Compat::IsHVCIEnabled())
                return DirectSyscall;

            if (Win11Compat::RequiresEnhancedEvasion())
                return FreshCopy;

            return UnhookNtdll;
        }

        return UnhookNtdll;
    }

    static bool IsEvasionRequired()
    {
        return Win11Compat::IsWindows11OrGreater() ||
               Win11Compat::IsVBSEnabled() ||
               Win11Compat::IsHVCIEnabled();
    }
};
