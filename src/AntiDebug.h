#pragma once

#include <Windows.h>
#include "Win11Compat.h"
#include <BlackBone/Process/Process.h>

class AntiDebug
{
public:
    static bool IsProcessBeingDebugged( blackbone::Process& process )
    {
        if (process.core().isWow64())
            return IsDebuggedWow64( process );
        else
            return IsDebuggedNative( process );
    }

    static NTSTATUS DisableDebuggerAttach( blackbone::Process& process )
    {
        auto ntdll = process.modules().GetModule( L"ntdll.dll" );
        if (!ntdll)
            return STATUS_DLL_NOT_FOUND;

        auto dbgUiProcResult = process.modules().GetExport( ntdll, "DbgUiRemoteBreakin" );
        if (!dbgUiProcResult.success())
            return STATUS_PROCEDURE_NOT_FOUND;

        auto dbgUiProc = dbgUiProcResult.result();

        uint8_t retOp = 0xC3;
        return process.memory().Write( dbgUiProc.procAddress, sizeof( retOp ), &retOp );
    }

    static NTSTATUS ClearDebugPort( blackbone::Process& process )
    {
        typedef NTSTATUS( NTAPI* pfnNtSetInformationProcess )(
            HANDLE ProcessHandle,
            DWORD ProcessInformationClass,
            PVOID ProcessInformation,
            ULONG ProcessInformationLength
            );

        auto ntdll = GetModuleHandleW( L"ntdll.dll" );
        if (!ntdll)
            return STATUS_DLL_NOT_FOUND;

        auto pNtSet = reinterpret_cast<pfnNtSetInformationProcess>(
            GetProcAddress( ntdll, "NtSetInformationProcess" ) );

        if (!pNtSet)
            return STATUS_PROCEDURE_NOT_FOUND;

        HANDLE hProcess = process.core().handle();
        ULONG debugPort = 0;

        return pNtSet( hProcess, 7, &debugPort, sizeof( debugPort ) );
    }

    static NTSTATUS HideThreadFromDebugger( HANDLE hThread )
    {
        typedef NTSTATUS( NTAPI* pfnNtSetInformationThread )(
            HANDLE ThreadHandle,
            DWORD ThreadInformationClass,
            PVOID ThreadInformation,
            ULONG ThreadInformationLength
            );

        auto ntdll = GetModuleHandleW( L"ntdll.dll" );
        if (!ntdll)
            return STATUS_DLL_NOT_FOUND;

        auto pNtSet = reinterpret_cast<pfnNtSetInformationThread>(
            GetProcAddress( ntdll, "NtSetInformationThread" ) );

        if (!pNtSet)
            return STATUS_PROCEDURE_NOT_FOUND;

        return pNtSet( hThread, 0x11, nullptr, 0 );
    }

private:
    static bool IsDebuggedWow64( blackbone::Process& process )
    {
        blackbone::_PEB32 peb = { 0 };
        if (!NT_SUCCESS( process.core().peb32( &peb ) ))
            return false;

        return peb.BeingDebugged != 0;
    }

    static bool IsDebuggedNative( blackbone::Process& process )
    {
        blackbone::_PEB64 peb = { 0 };
        if (!NT_SUCCESS( process.core().peb64( &peb ) ))
            return false;

        return peb.BeingDebugged != 0;
    }

public:
    static NTSTATUS DisableAllDebugFeatures( blackbone::Process& process )
    {
        NTSTATUS status = STATUS_SUCCESS;

        if (IsProcessBeingDebugged( process ))
        {
            status = DisableDebuggerAttach( process );
            if (!NT_SUCCESS( status ))
                return status;

            status = ClearDebugPort( process );
            if (!NT_SUCCESS( status ))
                return status;
        }

        return status;
    }

    static bool IsRemoteDebuggerPresent( blackbone::Process& process )
    {
        typedef NTSTATUS( NTAPI* pfnNtQueryInformationProcess )(
            HANDLE ProcessHandle,
            DWORD ProcessInformationClass,
            PVOID ProcessInformation,
            ULONG ProcessInformationLength,
            PULONG ReturnLength
            );

        auto ntdll = GetModuleHandleW( L"ntdll.dll" );
        if (!ntdll)
            return false;

        auto pNtQuery = reinterpret_cast<pfnNtQueryInformationProcess>(
            GetProcAddress( ntdll, "NtQueryInformationProcess" ) );

        if (!pNtQuery)
            return false;

        HANDLE debugPort = nullptr;
        ULONG returnLength = 0;

        NTSTATUS status = pNtQuery(
            process.core().handle(),
            7,
            &debugPort,
            sizeof( debugPort ),
            &returnLength
            );

        return NT_SUCCESS( status ) && debugPort != nullptr;
    }

    static NTSTATUS PatchNtQueryInformationProcess( blackbone::Process& process )
    {
        auto ntdll = process.modules().GetModule( L"ntdll.dll" );
        if (!ntdll)
            return STATUS_DLL_NOT_FOUND;

        auto exportResult = process.modules().GetExport( ntdll, "NtQueryInformationProcess" );
        if (!exportResult.success())
            return STATUS_PROCEDURE_NOT_FOUND;

        auto exportAddr = exportResult.result().procAddress;

        uint8_t patch[] = { 0x33, 0xC0, 0xC3 };
        return process.memory().Write( exportAddr, sizeof( patch ), patch );
    }

    static bool RequiresAntiDebug()
    {
        return Win11Compat::IsWindows11OrGreater() ||
               Win11Compat::RequiresEnhancedEvasion();
    }
};
