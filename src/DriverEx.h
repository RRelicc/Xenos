#pragma once

#include "Win11Compat.h"
#include "RetryHelper.h"
#include <BlackBone/DriverControl/DriverControl.h>
#include <string>

class DriverEx
{
public:
    static NTSTATUS LoadDriverSafe( const std::wstring& driverPath )
    {
        if (Win11Compat::IsHVCIEnabled())
        {
            return STATUS_NOT_SUPPORTED;
        }

        if (Win11Compat::IsVBSEnabled())
        {
            return STATUS_NOT_SUPPORTED;
        }

        if (!Win11Compat::IsProcessElevated())
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        auto& driver = blackbone::Driver::Instance();
        return driver.EnsureLoaded( driverPath );
    }

    static NTSTATUS UnloadDriver()
    {
        auto& driver = blackbone::Driver::Instance();
        return driver.Unload();
    }

    static bool IsDriverLoaded()
    {
        auto& driver = blackbone::Driver::Instance();
        return driver.loaded();
    }

    static NTSTATUS ReloadDriver( const std::wstring& driverPath )
    {
        UnloadDriver();
        Sleep( 100 );
        return LoadDriverSafe( driverPath );
    }

    static NTSTATUS LoadWithRetry(
        const std::wstring& driverPath,
        int maxRetries = 0
        )
    {
        if (maxRetries == 0)
            maxRetries = RetryHelper::GetRecommendedRetries();

        return RetryHelper::Retry(
            [&]() { return LoadDriverSafe( driverPath ); },
            maxRetries,
            RetryHelper::GetRecommendedDelay(),
            RetryHelper::IsRetryableStatus
        );
    }

    static bool CanLoadDriver()
    {
        if (!Win11Compat::IsProcessElevated())
            return false;

        if (Win11Compat::IsHVCIEnabled())
            return false;

        if (Win11Compat::IsVBSEnabled())
            return false;

        return true;
    }

    static NTSTATUS ProtectProcess( DWORD pid, bool protect )
    {
        if (!IsDriverLoaded())
            return STATUS_DEVICE_NOT_READY;

        auto& driver = blackbone::Driver::Instance();
        return protect ? driver.ProtectProcess( pid, true ) : driver.ProtectProcess( pid, false );
    }

    static NTSTATUS UnlinkHandleTable( DWORD pid )
    {
        if (!IsDriverLoaded())
            return STATUS_DEVICE_NOT_READY;

        auto& driver = blackbone::Driver::Instance();
        return driver.UnlinkHandleTable( pid );
    }

    static NTSTATUS PromoteHandle(
        DWORD sourcePid,
        DWORD targetPid,
        HANDLE sourceHandle,
        DWORD access,
        HANDLE& resultHandle
        )
    {
        if (!IsDriverLoaded())
            return STATUS_DEVICE_NOT_READY;

        auto& driver = blackbone::Driver::Instance();
        return driver.PromoteHandle( sourcePid, targetPid, sourceHandle, access, &resultHandle );
    }

    static NTSTATUS AllocateMemory(
        DWORD pid,
        blackbone::ptr_t& address,
        size_t size,
        DWORD protection
        )
    {
        if (!IsDriverLoaded())
            return STATUS_DEVICE_NOT_READY;

        auto& driver = blackbone::Driver::Instance();
        return driver.AllocateMem( pid, address, size, protection, false );
    }

    static NTSTATUS ReadMemory(
        DWORD pid,
        blackbone::ptr_t address,
        void* buffer,
        size_t size
        )
    {
        if (!IsDriverLoaded())
            return STATUS_DEVICE_NOT_READY;

        auto& driver = blackbone::Driver::Instance();
        return driver.ReadMem( pid, address, size, buffer );
    }

    static NTSTATUS WriteMemory(
        DWORD pid,
        blackbone::ptr_t address,
        const void* buffer,
        size_t size
        )
    {
        if (!IsDriverLoaded())
            return STATUS_DEVICE_NOT_READY;

        auto& driver = blackbone::Driver::Instance();
        return driver.WriteMem( pid, address, size, const_cast<void*>(buffer) );
    }

    static NTSTATUS MapMemory(
        DWORD pid,
        blackbone::ptr_t& address,
        size_t size,
        DWORD protection
        )
    {
        if (!IsDriverLoaded())
            return STATUS_DEVICE_NOT_READY;

        auto& driver = blackbone::Driver::Instance();
        return driver.MapMemory( pid, address, size, protection );
    }

    static std::wstring GetDriverPath()
    {
        auto& driver = blackbone::Driver::Instance();
        return driver.GetDriverPath();
    }

    static NTSTATUS GrantAccess( DWORD pid, DWORD access )
    {
        if (!IsDriverLoaded())
            return STATUS_DEVICE_NOT_READY;

        auto& driver = blackbone::Driver::Instance();
        return driver.GrantAccess( pid, access );
    }

    static NTSTATUS ExecuteInKernel( void* code, size_t size )
    {
        if (!IsDriverLoaded())
            return STATUS_DEVICE_NOT_READY;

        auto& driver = blackbone::Driver::Instance();
        return driver.ExecuteInKernelMode( code, size );
    }
};
