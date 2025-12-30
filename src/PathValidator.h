#pragma once

#include <string>
#include <Windows.h>
#include <Shlwapi.h>
#include <algorithm>
#include "Win11Compat.h"

#pragma comment(lib, "Shlwapi.lib")

class PathValidator
{
public:
    static bool IsValidPath( const std::wstring& path )
    {
        if (path.empty() || path.length() >= MAX_PATH)
            return false;

        if (path.find( L'\0' ) != std::wstring::npos)
            return false;

        const wchar_t invalidChars[] = L"<>|\"";
        if (path.find_first_of( invalidChars ) != std::wstring::npos)
            return false;

        return true;
    }

    static bool FileExists( const std::wstring& path )
    {
        if (!IsValidPath( path ))
            return false;

        DWORD attrs = GetFileAttributesW( path.c_str() );
        return (attrs != INVALID_FILE_ATTRIBUTES) && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
    }

    static bool DirectoryExists( const std::wstring& path )
    {
        if (!IsValidPath( path ))
            return false;

        DWORD attrs = GetFileAttributesW( path.c_str() );
        return (attrs != INVALID_FILE_ATTRIBUTES) && (attrs & FILE_ATTRIBUTE_DIRECTORY);
    }

    static std::wstring NormalizePath( const std::wstring& path )
    {
        if (path.length() >= MAX_PATH)
            return path;

        wchar_t normalized[MAX_PATH] = { 0 };

        if (PathCanonicalizeW( normalized, path.c_str() ))
            return std::wstring( normalized );

        return path;
    }

    static bool IsSafePath( const std::wstring& path )
    {
        std::wstring normalized = NormalizePath( path );

        if (normalized.find( L".." ) != std::wstring::npos)
            return false;

        wchar_t systemDir[MAX_PATH] = { 0 };
        GetSystemDirectoryW( systemDir, MAX_PATH );

        wchar_t windowsDir[MAX_PATH] = { 0 };
        GetWindowsDirectoryW( windowsDir, MAX_PATH );

        std::wstring normalizedLower = normalized;
        std::transform( normalizedLower.begin(), normalizedLower.end(), normalizedLower.begin(), ::towlower );

        std::wstring sysDirLower = systemDir;
        std::transform( sysDirLower.begin(), sysDirLower.end(), sysDirLower.begin(), ::towlower );

        std::wstring winDirLower = windowsDir;
        std::transform( winDirLower.begin(), winDirLower.end(), winDirLower.begin(), ::towlower );

        if (normalizedLower.find( sysDirLower ) == 0 || normalizedLower.find( winDirLower ) == 0)
            return false;

        return true;
    }

    static std::wstring GetExtension( const std::wstring& path )
    {
        size_t pos = path.find_last_of( L'.' );
        if (pos == std::wstring::npos || pos == path.length() - 1)
            return L"";

        return path.substr( pos + 1 );
    }

    static bool HasValidImageExtension( const std::wstring& path )
    {
        std::wstring ext = GetExtension( path );
        std::transform( ext.begin(), ext.end(), ext.begin(), ::towlower );

        return ext == L"dll" || ext == L"exe" || ext == L"sys";
    }

    static std::wstring GetAbsolutePath( const std::wstring& path )
    {
        if (path.length() >= MAX_PATH)
            return path;

        wchar_t fullPath[MAX_PATH] = { 0 };

        if (GetFullPathNameW( path.c_str(), MAX_PATH, fullPath, nullptr ))
            return std::wstring( fullPath );

        return path;
    }

    static std::wstring GetFileName( const std::wstring& path )
    {
        size_t pos = path.find_last_of( L"\\/" );
        if (pos == std::wstring::npos)
            return path;

        return path.substr( pos + 1 );
    }

    static std::wstring GetDirectory( const std::wstring& path )
    {
        size_t pos = path.find_last_of( L"\\/" );
        if (pos == std::wstring::npos)
            return L"";

        return path.substr( 0, pos );
    }

    static ULONGLONG GetFileSize( const std::wstring& path )
    {
        WIN32_FILE_ATTRIBUTE_DATA fad = { 0 };

        if (!GetFileAttributesExW( path.c_str(), GetFileExInfoStandard, &fad ))
            return 0;

        ULARGE_INTEGER size;
        size.HighPart = fad.nFileSizeHigh;
        size.LowPart = fad.nFileSizeLow;

        return size.QuadPart;
    }

    static bool IsWriteable( const std::wstring& path )
    {
        HANDLE hFile = CreateFileW( path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr );
        if (hFile == INVALID_HANDLE_VALUE)
            return false;

        CloseHandle( hFile );
        return true;
    }

    static bool IsProtectedLocation( const std::wstring& path )
    {
        std::wstring normalized = NormalizePath( path );
        std::transform( normalized.begin(), normalized.end(), normalized.begin(), ::towlower );

        if (normalized.find( L"\\windows\\system32" ) != std::wstring::npos)
            return true;

        if (normalized.find( L"\\windows\\syswow64" ) != std::wstring::npos)
            return true;

        if (normalized.find( L"\\program files" ) != std::wstring::npos)
            return true;

        return false;
    }
};
