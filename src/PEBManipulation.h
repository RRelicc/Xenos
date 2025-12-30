#pragma once

#include "Win11Compat.h"
#include <BlackBone/Process/Process.h>
#include <BlackBone/Misc/Utils.h>
#include <vector>

class PEBManipulation
{
public:
    static NTSTATUS UnlinkModuleFromPEB(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase
        )
    {
        auto peb = process.core().peb();
        if (!peb)
            return STATUS_UNSUCCESSFUL;

        if (process.core().isWow64())
            return UnlinkModuleFromPEB32( process, moduleBase, peb->PEB32 );
        else
            return UnlinkModuleFromPEB64( process, moduleBase, peb->PEB64 );
    }

    static NTSTATUS RelinkModuleToPEB(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase
        )
    {
        auto peb = process.core().peb();
        if (!peb)
            return STATUS_UNSUCCESSFUL;

        auto mod = process.modules().GetModule( moduleBase );
        if (!mod)
            return STATUS_NOT_FOUND;

        return process.modules().Reload();
    }

    static NTSTATUS HideModuleFromPEB(
        blackbone::Process& process,
        const std::wstring& moduleName
        )
    {
        auto mod = process.modules().GetModule( moduleName );
        if (!mod)
            return STATUS_NOT_FOUND;

        return UnlinkModuleFromPEB( process, mod->baseAddress );
    }

    static NTSTATUS SpoofPEBImagePath(
        blackbone::Process& process,
        const std::wstring& newPath
        )
    {
        if (newPath.empty() || newPath.size() > 32767)
            return STATUS_INVALID_PARAMETER;

        auto peb = process.core().peb();
        if (!peb)
            return STATUS_UNSUCCESSFUL;

        if (process.core().isWow64())
        {
            _PEB32 pebData = { 0 };
            if (!NT_SUCCESS( process.memory().Read( peb->PEB32, sizeof( pebData ), &pebData ) ))
                return STATUS_MEMORY_NOT_ALLOCATED;

            _RTL_USER_PROCESS_PARAMETERS32 params = { 0 };
            if (!NT_SUCCESS( process.memory().Read( pebData.ProcessParameters, sizeof( params ), &params ) ))
                return STATUS_MEMORY_NOT_ALLOCATED;

            auto newPathMem = process.memory().Allocate( (newPath.size() + 1) * sizeof( wchar_t ), PAGE_READWRITE );
            if (!newPathMem)
                return STATUS_MEMORY_NOT_ALLOCATED;

            process.memory().Write( newPathMem->ptr(), newPath.size() * sizeof( wchar_t ), newPath.c_str() );

            params.ImagePathName.Buffer = static_cast<uint32_t>(newPathMem->ptr());
            params.ImagePathName.Length = static_cast<USHORT>(newPath.size() * sizeof( wchar_t ));
            params.ImagePathName.MaximumLength = static_cast<USHORT>((newPath.size() + 1) * sizeof( wchar_t ));

            return process.memory().Write( pebData.ProcessParameters, sizeof( params ), &params );
        }
        else
        {
            _PEB64 pebData = { 0 };
            if (!NT_SUCCESS( process.memory().Read( peb->PEB64, sizeof( pebData ), &pebData ) ))
                return STATUS_MEMORY_NOT_ALLOCATED;

            _RTL_USER_PROCESS_PARAMETERS64 params = { 0 };
            if (!NT_SUCCESS( process.memory().Read( pebData.ProcessParameters, sizeof( params ), &params ) ))
                return STATUS_MEMORY_NOT_ALLOCATED;

            auto newPathMem = process.memory().Allocate( (newPath.size() + 1) * sizeof( wchar_t ), PAGE_READWRITE );
            if (!newPathMem)
                return STATUS_MEMORY_NOT_ALLOCATED;

            process.memory().Write( newPathMem->ptr(), newPath.size() * sizeof( wchar_t ), newPath.c_str() );

            params.ImagePathName.Buffer = newPathMem->ptr();
            params.ImagePathName.Length = static_cast<USHORT>(newPath.size() * sizeof( wchar_t ));
            params.ImagePathName.MaximumLength = static_cast<USHORT>((newPath.size() + 1) * sizeof( wchar_t ));

            return process.memory().Write( pebData.ProcessParameters, sizeof( params ), &params );
        }
    }

    static NTSTATUS SpoofPEBCommandLine(
        blackbone::Process& process,
        const std::wstring& newCommandLine
        )
    {
        if (newCommandLine.size() > 32767)
            return STATUS_INVALID_PARAMETER;

        auto peb = process.core().peb();
        if (!peb)
            return STATUS_UNSUCCESSFUL;

        if (process.core().isWow64())
        {
            _PEB32 pebData = { 0 };
            if (!NT_SUCCESS( process.memory().Read( peb->PEB32, sizeof( pebData ), &pebData ) ))
                return STATUS_MEMORY_NOT_ALLOCATED;

            _RTL_USER_PROCESS_PARAMETERS32 params = { 0 };
            if (!NT_SUCCESS( process.memory().Read( pebData.ProcessParameters, sizeof( params ), &params ) ))
                return STATUS_MEMORY_NOT_ALLOCATED;

            auto newCmdMem = process.memory().Allocate( (newCommandLine.size() + 1) * sizeof( wchar_t ), PAGE_READWRITE );
            if (!newCmdMem)
                return STATUS_MEMORY_NOT_ALLOCATED;

            process.memory().Write( newCmdMem->ptr(), newCommandLine.size() * sizeof( wchar_t ), newCommandLine.c_str() );

            params.CommandLine.Buffer = static_cast<uint32_t>(newCmdMem->ptr());
            params.CommandLine.Length = static_cast<USHORT>(newCommandLine.size() * sizeof( wchar_t ));
            params.CommandLine.MaximumLength = static_cast<USHORT>((newCommandLine.size() + 1) * sizeof( wchar_t ));

            return process.memory().Write( pebData.ProcessParameters, sizeof( params ), &params );
        }
        else
        {
            _PEB64 pebData = { 0 };
            if (!NT_SUCCESS( process.memory().Read( peb->PEB64, sizeof( pebData ), &pebData ) ))
                return STATUS_MEMORY_NOT_ALLOCATED;

            _RTL_USER_PROCESS_PARAMETERS64 params = { 0 };
            if (!NT_SUCCESS( process.memory().Read( pebData.ProcessParameters, sizeof( params ), &params ) ))
                return STATUS_MEMORY_NOT_ALLOCATED;

            auto newCmdMem = process.memory().Allocate( (newCommandLine.size() + 1) * sizeof( wchar_t ), PAGE_READWRITE );
            if (!newCmdMem)
                return STATUS_MEMORY_NOT_ALLOCATED;

            process.memory().Write( newCmdMem->ptr(), newCommandLine.size() * sizeof( wchar_t ), newCommandLine.c_str() );

            params.CommandLine.Buffer = newCmdMem->ptr();
            params.CommandLine.Length = static_cast<USHORT>(newCommandLine.size() * sizeof( wchar_t ));
            params.CommandLine.MaximumLength = static_cast<USHORT>((newCommandLine.size() + 1) * sizeof( wchar_t ));

            return process.memory().Write( pebData.ProcessParameters, sizeof( params ), &params );
        }
    }

    static NTSTATUS ClearPEBBeingDebugged(
        blackbone::Process& process
        )
    {
        auto peb = process.core().peb();
        if (!peb)
            return STATUS_UNSUCCESSFUL;

        uint8_t zero = 0;

        if (process.core().isWow64())
        {
            return process.memory().Write( peb->PEB32 + offsetof( _PEB32, BeingDebugged ), sizeof( zero ), &zero );
        }
        else
        {
            return process.memory().Write( peb->PEB64 + offsetof( _PEB64, BeingDebugged ), sizeof( zero ), &zero );
        }
    }

    static NTSTATUS GetPEBModuleList(
        blackbone::Process& process,
        std::vector<blackbone::ptr_t>& moduleList
        )
    {
        auto peb = process.core().peb();
        if (!peb)
            return STATUS_UNSUCCESSFUL;

        if (process.core().isWow64())
            return GetPEBModuleList32( process, peb->PEB32, moduleList );
        else
            return GetPEBModuleList64( process, peb->PEB64, moduleList );
    }

private:
    static NTSTATUS UnlinkModuleFromPEB64(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase,
        blackbone::ptr_t pebAddress
        )
    {
        _PEB64 peb = { 0 };
        if (!NT_SUCCESS( process.memory().Read( pebAddress, sizeof( peb ), &peb ) ))
            return STATUS_MEMORY_NOT_ALLOCATED;

        _PEB_LDR_DATA64 ldr = { 0 };
        if (!NT_SUCCESS( process.memory().Read( peb.Ldr, sizeof( ldr ), &ldr ) ))
            return STATUS_MEMORY_NOT_ALLOCATED;

        blackbone::ptr_t head = peb.Ldr + offsetof( _PEB_LDR_DATA64, InLoadOrderModuleList );
        blackbone::ptr_t current = ldr.InLoadOrderModuleList.Flink;

        while (current != head)
        {
            _LDR_DATA_TABLE_ENTRY64 entry = { 0 };
            if (!NT_SUCCESS( process.memory().Read( current, sizeof( entry ), &entry ) ))
                break;

            if (entry.DllBase == moduleBase)
            {
                blackbone::ptr_t flink = entry.InLoadOrderLinks.Flink;
                blackbone::ptr_t blink = entry.InLoadOrderLinks.Blink;

                process.memory().Write( flink + sizeof( blackbone::ptr_t ), sizeof( blink ), &blink );
                process.memory().Write( blink, sizeof( flink ), &flink );

                flink = entry.InMemoryOrderLinks.Flink;
                blink = entry.InMemoryOrderLinks.Blink;

                process.memory().Write( flink + sizeof( blackbone::ptr_t ), sizeof( blink ), &blink );
                process.memory().Write( blink, sizeof( flink ), &flink );

                flink = entry.InInitializationOrderLinks.Flink;
                blink = entry.InInitializationOrderLinks.Blink;

                process.memory().Write( flink + sizeof( blackbone::ptr_t ), sizeof( blink ), &blink );
                process.memory().Write( blink, sizeof( flink ), &flink );

                return STATUS_SUCCESS;
            }

            current = entry.InLoadOrderLinks.Flink;
        }

        return STATUS_NOT_FOUND;
    }

    static NTSTATUS UnlinkModuleFromPEB32(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase,
        blackbone::ptr_t pebAddress
        )
    {
        _PEB32 peb = { 0 };
        if (!NT_SUCCESS( process.memory().Read( pebAddress, sizeof( peb ), &peb ) ))
            return STATUS_MEMORY_NOT_ALLOCATED;

        _PEB_LDR_DATA32 ldr = { 0 };
        if (!NT_SUCCESS( process.memory().Read( peb.Ldr, sizeof( ldr ), &ldr ) ))
            return STATUS_MEMORY_NOT_ALLOCATED;

        uint32_t head = static_cast<uint32_t>(peb.Ldr + offsetof( _PEB_LDR_DATA32, InLoadOrderModuleList ));
        uint32_t current = ldr.InLoadOrderModuleList.Flink;

        while (current != head)
        {
            _LDR_DATA_TABLE_ENTRY32 entry = { 0 };
            if (!NT_SUCCESS( process.memory().Read( current, sizeof( entry ), &entry ) ))
                break;

            if (entry.DllBase == static_cast<uint32_t>(moduleBase))
            {
                uint32_t flink = entry.InLoadOrderLinks.Flink;
                uint32_t blink = entry.InLoadOrderLinks.Blink;

                process.memory().Write( flink + sizeof( uint32_t ), sizeof( blink ), &blink );
                process.memory().Write( blink, sizeof( flink ), &flink );

                flink = entry.InMemoryOrderLinks.Flink;
                blink = entry.InMemoryOrderLinks.Blink;

                process.memory().Write( flink + sizeof( uint32_t ), sizeof( blink ), &blink );
                process.memory().Write( blink, sizeof( flink ), &flink );

                flink = entry.InInitializationOrderLinks.Flink;
                blink = entry.InInitializationOrderLinks.Blink;

                process.memory().Write( flink + sizeof( uint32_t ), sizeof( blink ), &blink );
                process.memory().Write( blink, sizeof( flink ), &flink );

                return STATUS_SUCCESS;
            }

            current = entry.InLoadOrderLinks.Flink;
        }

        return STATUS_NOT_FOUND;
    }

    static NTSTATUS GetPEBModuleList64(
        blackbone::Process& process,
        blackbone::ptr_t pebAddress,
        std::vector<blackbone::ptr_t>& moduleList
        )
    {
        _PEB64 peb = { 0 };
        if (!NT_SUCCESS( process.memory().Read( pebAddress, sizeof( peb ), &peb ) ))
            return STATUS_MEMORY_NOT_ALLOCATED;

        _PEB_LDR_DATA64 ldr = { 0 };
        if (!NT_SUCCESS( process.memory().Read( peb.Ldr, sizeof( ldr ), &ldr ) ))
            return STATUS_MEMORY_NOT_ALLOCATED;

        blackbone::ptr_t head = peb.Ldr + offsetof( _PEB_LDR_DATA64, InLoadOrderModuleList );
        blackbone::ptr_t current = ldr.InLoadOrderModuleList.Flink;

        while (current != head)
        {
            _LDR_DATA_TABLE_ENTRY64 entry = { 0 };
            if (!NT_SUCCESS( process.memory().Read( current, sizeof( entry ), &entry ) ))
                break;

            moduleList.push_back( entry.DllBase );

            current = entry.InLoadOrderLinks.Flink;
        }

        return STATUS_SUCCESS;
    }

    static NTSTATUS GetPEBModuleList32(
        blackbone::Process& process,
        blackbone::ptr_t pebAddress,
        std::vector<blackbone::ptr_t>& moduleList
        )
    {
        _PEB32 peb = { 0 };
        if (!NT_SUCCESS( process.memory().Read( pebAddress, sizeof( peb ), &peb ) ))
            return STATUS_MEMORY_NOT_ALLOCATED;

        _PEB_LDR_DATA32 ldr = { 0 };
        if (!NT_SUCCESS( process.memory().Read( peb.Ldr, sizeof( ldr ), &ldr ) ))
            return STATUS_MEMORY_NOT_ALLOCATED;

        uint32_t head = static_cast<uint32_t>(peb.Ldr + offsetof( _PEB_LDR_DATA32, InLoadOrderModuleList ));
        uint32_t current = ldr.InLoadOrderModuleList.Flink;

        while (current != head)
        {
            _LDR_DATA_TABLE_ENTRY32 entry = { 0 };
            if (!NT_SUCCESS( process.memory().Read( current, sizeof( entry ), &entry ) ))
                break;

            moduleList.push_back( entry.DllBase );

            current = entry.InLoadOrderLinks.Flink;
        }

        return STATUS_SUCCESS;
    }
};
