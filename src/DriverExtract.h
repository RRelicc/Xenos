#pragma once

#include "resource.h"
#include "Win11Compat.h"
#include <3rd_party/VersionApi.h>
#include <BlackBone/DriverControl/DriverControl.h>

class DriverExtract
{
public:
    static DriverExtract& Instance()
    {
        static DriverExtract inst;
        return inst;
    }

    /// <summary>
    /// Extracts required driver version form self
    /// </summary>
    bool Extract()
    {
        const wchar_t* filename = nullptr;
        int resID = 0;
        GetDriverInfo( filename, resID );

        HRSRC resInfo = FindResourceW( NULL, MAKEINTRESOURCEW( resID ), L"Driver" );
        if (!resInfo)
            return false;

        HGLOBAL hRes = LoadResource( NULL, resInfo );
        if (!hRes)
            return false;

        PVOID pDriverData = LockResource( hRes );
        if (!pDriverData)
            return false;

        DWORD resourceSize = SizeofResource( NULL, resInfo );
        if (resourceSize == 0)
            return false;

        HANDLE hFile = CreateFileW(
            (blackbone::Utils::GetExeDirectory() + L"\\" + filename).c_str(),
            FILE_GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL
            );

        if (hFile == INVALID_HANDLE_VALUE)
            return false;

        DWORD bytes = 0;
        BOOL writeSuccess = WriteFile( hFile, pDriverData, resourceSize, &bytes, NULL );
        CloseHandle( hFile );

        return writeSuccess && (bytes == resourceSize);
    }


    ~DriverExtract()
    {
        Cleanup();
    }

    /// <summary>
    /// Remove unpacked driver, if any
    /// </summary>
    void Cleanup()
    {
        const wchar_t* filename = nullptr;
        int resID = 0;
        GetDriverInfo( filename, resID );

        DeleteFileW( (blackbone::Utils::GetExeDirectory() + L"\\" + filename).c_str() );
    }

private:
    void GetDriverInfo( const wchar_t*& filename, int& resID )
    {
        auto version = Win11Compat::GetWindowsVersion();

        if (version >= Win11Compat::WindowsVersion::Win11)
        {
            filename = L"BlackBoneDrv10.sys";
            resID = IDR_DRV10;
        }
        else if (version >= Win11Compat::WindowsVersion::Win10)
        {
            filename = L"BlackBoneDrv10.sys";
            resID = IDR_DRV10;
        }
        else if (version >= Win11Compat::WindowsVersion::Win8_1)
        {
            filename = L"BlackBoneDrv81.sys";
            resID = IDR_DRV81;
        }
        else if (version >= Win11Compat::WindowsVersion::Win8)
        {
            filename = L"BlackBoneDrv8.sys";
            resID = IDR_DRV8;
        }
        else
        {
            filename = L"BlackBoneDrv7.sys";
            resID = IDR_DRV7;
        }
    }

    DriverExtract() = default;
    DriverExtract( const DriverExtract& ) = delete;
    DriverExtract& operator=( const DriverExtract& ) = delete;
};
