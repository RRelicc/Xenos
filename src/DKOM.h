#pragma once

#include "Win11Compat.h"
#include <BlackBone/Process/Process.h>
#include <BlackBone/Driver/DriverControl.h>

class DKOM
{
public:
    static bool IsDriverAvailable()
    {
        blackbone::DriverControl driver;
        return NT_SUCCESS( driver.EnsureLoaded() );
    }

    static NTSTATUS HideProcessFromEPROCESS(
        DWORD pid
        )
    {
        if (!IsDriverAvailable())
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        blackbone::DriverControl driver;
        if (!NT_SUCCESS( driver.EnsureLoaded() ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        return driver.UnlinkProcess( pid );
    }

    static NTSTATUS ProtectProcess(
        DWORD pid,
        bool protect
        )
    {
        if (!IsDriverAvailable())
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        blackbone::DriverControl driver;
        if (!NT_SUCCESS( driver.EnsureLoaded() ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        return driver.ProtectProcess( pid, protect );
    }

    static NTSTATUS GrantHandleAccess(
        HANDLE handle,
        DWORD access
        )
    {
        if (!IsDriverAvailable())
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        blackbone::DriverControl driver;
        if (!NT_SUCCESS( driver.EnsureLoaded() ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        return driver.PromoteHandle( GetCurrentProcessId(), handle, access );
    }

    static NTSTATUS AllocateKernelMemory(
        size_t size,
        blackbone::ptr_t& outAddress
        )
    {
        if (!IsDriverAvailable())
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        blackbone::DriverControl driver;
        if (!NT_SUCCESS( driver.EnsureLoaded() ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        return driver.AllocateMemory( size, false, &outAddress );
    }

    static NTSTATUS FreeKernelMemory(
        blackbone::ptr_t address
        )
    {
        if (!IsDriverAvailable())
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        blackbone::DriverControl driver;
        if (!NT_SUCCESS( driver.EnsureLoaded() ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        return driver.FreeMemory( address );
    }

    static NTSTATUS ReadKernelMemory(
        blackbone::ptr_t address,
        void* buffer,
        size_t size
        )
    {
        if (!IsDriverAvailable())
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        blackbone::DriverControl driver;
        if (!NT_SUCCESS( driver.EnsureLoaded() ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        return driver.ReadMem( address, size, buffer );
    }

    static NTSTATUS WriteKernelMemory(
        blackbone::ptr_t address,
        const void* buffer,
        size_t size
        )
    {
        if (!IsDriverAvailable())
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        blackbone::DriverControl driver;
        if (!NT_SUCCESS( driver.EnsureLoaded() ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        return driver.WriteMem( address, size, const_cast<void*>(buffer) );
    }

    static NTSTATUS DisableDriverSignatureEnforcement()
    {
        if (!IsDriverAvailable())
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        blackbone::DriverControl driver;
        if (!NT_SUCCESS( driver.EnsureLoaded() ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        return driver.DisableDSE();
    }

    static NTSTATUS EnableDriverSignatureEnforcement()
    {
        if (!IsDriverAvailable())
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        blackbone::DriverControl driver;
        if (!NT_SUCCESS( driver.EnsureLoaded() ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        return driver.EnableDSE();
    }

    static NTSTATUS RemoveKernelCallback(
        blackbone::ptr_t callbackAddress
        )
    {
        if (!IsDriverAvailable())
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        blackbone::DriverControl driver;
        if (!NT_SUCCESS( driver.EnsureLoaded() ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        uint8_t nop = 0xC3;
        return driver.WriteMem( callbackAddress, sizeof( nop ), &nop );
    }

    static NTSTATUS MapDriverManually(
        const std::wstring& driverPath,
        blackbone::ptr_t& outBase
        )
    {
        if (!IsDriverAvailable())
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        blackbone::DriverControl driver;
        if (!NT_SUCCESS( driver.EnsureLoaded() ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        return driver.MMapDriver( driverPath, &outBase );
    }

    static NTSTATUS UnmapDriver(
        blackbone::ptr_t baseAddress
        )
    {
        if (!IsDriverAvailable())
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        blackbone::DriverControl driver;
        if (!NT_SUCCESS( driver.EnsureLoaded() ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        return driver.UnmapDriver( baseAddress );
    }

    static NTSTATUS HideDriver(
        const std::wstring& driverName
        )
    {
        if (!IsDriverAvailable())
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        blackbone::DriverControl driver;
        if (!NT_SUCCESS( driver.EnsureLoaded() ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        return STATUS_NOT_IMPLEMENTED;
    }

    static NTSTATUS PatchKernelFunction(
        const std::string& functionName,
        const std::vector<uint8_t>& patch
        )
    {
        if (!IsDriverAvailable())
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        blackbone::DriverControl driver;
        if (!NT_SUCCESS( driver.EnsureLoaded() ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        return STATUS_NOT_IMPLEMENTED;
    }

    static NTSTATUS GetKernelModuleBase(
        const std::wstring& moduleName,
        blackbone::ptr_t& outBase
        )
    {
        if (!IsDriverAvailable())
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        blackbone::DriverControl driver;
        if (!NT_SUCCESS( driver.EnsureLoaded() ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        return driver.GetKernelModule( moduleName, &outBase, nullptr );
    }

    static NTSTATUS ExecuteInKernelContext(
        blackbone::ptr_t functionAddress,
        blackbone::ptr_t argument
        )
    {
        if (!IsDriverAvailable())
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        blackbone::DriverControl driver;
        if (!NT_SUCCESS( driver.EnsureLoaded() ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        return STATUS_NOT_IMPLEMENTED;
    }

    static NTSTATUS BypassProcessProtection(
        DWORD pid
        )
    {
        if (!IsDriverAvailable())
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        if (Win11Compat::IsVBSEnabled() || Win11Compat::IsHVCIEnabled())
            return STATUS_NOT_SUPPORTED;

        blackbone::DriverControl driver;
        if (!NT_SUCCESS( driver.EnsureLoaded() ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        return driver.ProtectProcess( pid, false );
    }

    static NTSTATUS SetProcessMitigations(
        DWORD pid,
        DWORD mitigationFlags
        )
    {
        if (!IsDriverAvailable())
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        blackbone::DriverControl driver;
        if (!NT_SUCCESS( driver.EnsureLoaded() ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        return STATUS_NOT_IMPLEMENTED;
    }

    static NTSTATUS ClearPiDDBCacheTable()
    {
        if (!IsDriverAvailable())
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        if (Win11Compat::IsVBSEnabled() || Win11Compat::IsHVCIEnabled())
            return STATUS_NOT_SUPPORTED;

        blackbone::DriverControl driver;
        if (!NT_SUCCESS( driver.EnsureLoaded() ))
            return STATUS_DRIVER_UNABLE_TO_LOAD;

        return STATUS_NOT_IMPLEMENTED;
    }
};
