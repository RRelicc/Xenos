#pragma once

#include <Windows.h>
#include "Win11Compat.h"
#include <BlackBone/Config.h>
#include <BlackBone/DriverControl/DriverControl.h>
#include "../../../ext/blackbone/src/BlackBoneDrv/BlackBoneDef.h"

class PPLBypass
{
public:
    enum PPLLevel
    {
        None = 0,
        PPL = 1,
        PP = 2,
        PPL_Antimalware = 3
    };

    static bool IsProtectedProcess( HANDLE hProcess, PPLLevel* outLevel = nullptr )
    {
        if (!hProcess)
            return false;

        typedef struct _PS_PROTECTION
        {
            union
            {
                UCHAR Level;
                struct
                {
                    UCHAR Type : 3;
                    UCHAR Audit : 1;
                    UCHAR Signer : 4;
                };
            };
        } PS_PROTECTION;

        typedef enum _PROCESSINFOCLASS
        {
            ProcessProtectionInformation = 61
        } PROCESSINFOCLASS;

        typedef NTSTATUS( NTAPI* pfnNtQueryInformationProcess )(
            HANDLE ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
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

        PS_PROTECTION protection = { 0 };
        ULONG returnLength = 0;

        NTSTATUS status = pNtQuery(
            hProcess,
            ProcessProtectionInformation,
            &protection,
            sizeof( protection ),
            &returnLength
            );

        if (!NT_SUCCESS( status ))
            return false;

        if (outLevel)
        {
            if (protection.Type == 2)
                *outLevel = PPL;
            else if (protection.Type == 1)
                *outLevel = PP;
            else if (protection.Type == 2 && protection.Signer == 6)
                *outLevel = PPL_Antimalware;
            else
                *outLevel = None;
        }

        return protection.Level != 0;
    }

    static NTSTATUS RemovePPL( DWORD pid )
    {
        auto& driver = blackbone::Driver();

        NTSTATUS status = driver.EnsureLoaded();
        if (!NT_SUCCESS( status ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        return driver.ProtectProcess( pid, Policy_Disable );
    }

    static NTSTATUS BypassPPL( DWORD pid, HANDLE* outHandle )
    {
        PPLLevel level = None;
        HANDLE hProcess = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid );

        if (hProcess)
        {
            bool isProtected = IsProtectedProcess( hProcess, &level );
            CloseHandle( hProcess );

            if (!isProtected)
            {
                *outHandle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );
                return *outHandle ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
            }
        }

        NTSTATUS status = RemovePPL( pid );
        if (!NT_SUCCESS( status ))
            return status;

        Sleep( 50 );

        *outHandle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );
        return *outHandle ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    }

    static bool IsPPLSupported()
    {
        return Win11Compat::GetWindowsVersion() >= Win11Compat::WindowsVersion::Win8;
    }

    static bool IsWin11PPL()
    {
        return Win11Compat::IsWindows11OrGreater();
    }

    static NTSTATUS BypassPPLWithVBSCheck( DWORD pid, HANDLE* outHandle )
    {
        if (Win11Compat::IsVBSEnabled() || Win11Compat::IsHVCIEnabled())
        {
            return STATUS_NOT_SUPPORTED;
        }

        return BypassPPL( pid, outHandle );
    }
};
