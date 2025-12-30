#pragma once

#include "Win11Compat.h"
#include "HandleGuard.h"
#include <BlackBone/Process/Process.h>
#include <string>

class ProcessGhosting
{
public:
    static NTSTATUS CreateGhostProcess(
        const std::wstring& imagePath,
        const std::wstring& commandLine,
        DWORD& outPid
        )
    {
        if (!Win11Compat::IsWindows10OrGreater())
            return STATUS_NOT_SUPPORTED;

        HMODULE hNtdll = GetModuleHandleW( L"ntdll.dll" );
        if (!hNtdll)
            return STATUS_DLL_NOT_FOUND;

        typedef NTSTATUS( NTAPI* pfnNtCreateFile )(
            PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
            PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG
            );

        typedef NTSTATUS( NTAPI* pfnNtSetInformationFile )(
            HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS
            );

        typedef NTSTATUS( NTAPI* pfnNtCreateProcessEx )(
            PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, BOOLEAN
            );

        auto NtCreateFile = reinterpret_cast<pfnNtCreateFile>(GetProcAddress( hNtdll, "NtCreateFile" ));
        auto NtSetInformationFile = reinterpret_cast<pfnNtSetInformationFile>(GetProcAddress( hNtdll, "NtSetInformationFile" ));
        auto NtCreateProcessEx = reinterpret_cast<pfnNtCreateProcessEx>(GetProcAddress( hNtdll, "NtCreateProcessEx" ));

        if (!NtCreateFile || !NtSetInformationFile || !NtCreateProcessEx)
            return STATUS_PROCEDURE_NOT_FOUND;

        wchar_t tempPath[MAX_PATH];
        GetTempPathW( MAX_PATH, tempPath );

        wchar_t tempFile[MAX_PATH];
        wsprintfW( tempFile, L"%s\\ghost_%u.tmp", tempPath, GetTickCount() );

        UNICODE_STRING fileName;
        RtlInitUnicodeString( &fileName, tempFile );

        OBJECT_ATTRIBUTES objAttr = { 0 };
        InitializeObjectAttributes( &objAttr, &fileName, OBJ_CASE_INSENSITIVE, nullptr, nullptr );

        IO_STATUS_BLOCK iosb = { 0 };
        HANDLE hFile = nullptr;

        NTSTATUS status = NtCreateFile(
            &hFile,
            DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE,
            &objAttr,
            &iosb,
            nullptr,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_SUPERSEDE,
            FILE_SYNCHRONOUS_IO_NONALERT,
            nullptr,
            0
        );

        if (!NT_SUCCESS( status ))
            return status;

        FileHandle fileGuard( hFile );

        std::vector<uint8_t> imageData;
        HANDLE hSourceFile = CreateFileW( imagePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr );
        if (hSourceFile == INVALID_HANDLE_VALUE)
            return STATUS_OBJECT_NAME_NOT_FOUND;

        FileHandle sourceGuard( hSourceFile );

        DWORD fileSize = GetFileSize( hSourceFile, nullptr );
        imageData.resize( fileSize );

        DWORD bytesRead = 0;
        if (!ReadFile( hSourceFile, imageData.data(), fileSize, &bytesRead, nullptr ))
            return STATUS_UNSUCCESSFUL;

        DWORD bytesWritten = 0;
        if (!WriteFile( hFile, imageData.data(), fileSize, &bytesWritten, nullptr ))
            return STATUS_UNSUCCESSFUL;

        FILE_DISPOSITION_INFORMATION fdi = { 0 };
        fdi.DeleteFile = TRUE;

        status = NtSetInformationFile( hFile, &iosb, &fdi, sizeof( fdi ), FileDispositionInformation );
        if (!NT_SUCCESS( status ))
            return status;

        HANDLE hSection = nullptr;
        status = NtCreateSection(
            &hSection,
            SECTION_ALL_ACCESS,
            nullptr,
            nullptr,
            PAGE_READONLY,
            SEC_IMAGE,
            hFile
        );

        if (!NT_SUCCESS( status ))
            return status;

        HandleGuard<HANDLE, nullptr> sectionGuard( hSection );

        fileGuard.Close();

        HANDLE hProcess = nullptr;
        status = NtCreateProcessEx(
            &hProcess,
            PROCESS_ALL_ACCESS,
            nullptr,
            GetCurrentProcess(),
            0,
            hSection,
            nullptr,
            nullptr,
            FALSE
        );

        if (!NT_SUCCESS( status ))
            return status;

        outPid = GetProcessId( hProcess );
        CloseHandle( hProcess );

        return STATUS_SUCCESS;
    }

private:
    static NTSTATUS NTAPI NtCreateSection(
        PHANDLE SectionHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PLARGE_INTEGER MaximumSize,
        ULONG SectionPageProtection,
        ULONG AllocationAttributes,
        HANDLE FileHandle
        )
    {
        HMODULE hNtdll = GetModuleHandleW( L"ntdll.dll" );
        if (!hNtdll)
            return STATUS_DLL_NOT_FOUND;

        typedef NTSTATUS( NTAPI* pfnNtCreateSection )(
            PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE
            );

        auto pNtCreateSection = reinterpret_cast<pfnNtCreateSection>(GetProcAddress( hNtdll, "NtCreateSection" ));
        if (!pNtCreateSection)
            return STATUS_PROCEDURE_NOT_FOUND;

        return pNtCreateSection(
            SectionHandle,
            DesiredAccess,
            ObjectAttributes,
            MaximumSize,
            SectionPageProtection,
            AllocationAttributes,
            FileHandle
        );
    }
};
