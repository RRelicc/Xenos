#pragma once

#include "Win11Compat.h"
#include <BlackBone/Process/Process.h>
#include <BlackBone/PE/PEImage.h>
#include <vector>

class TLSCallbackSpoofing
{
public:
    static NTSTATUS HideTLSCallbacks(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase
        )
    {
        std::vector<uint8_t> headerBuffer( 0x1000 );

        NTSTATUS status = process.memory().Read( moduleBase, headerBuffer.size(), headerBuffer.data() );
        if (!NT_SUCCESS( status ))
            return status;

        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(headerBuffer.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return STATUS_INVALID_IMAGE_FORMAT;

        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(headerBuffer.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
            return STATUS_INVALID_IMAGE_FORMAT;

        DWORD tlsRva = 0;

#ifdef USE64
        if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            auto ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(ntHeaders);
            tlsRva = ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        }
#else
        if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            tlsRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        }
#endif

        if (tlsRva == 0)
            return STATUS_SUCCESS;

        IMAGE_TLS_DIRECTORY tlsDir = { 0 };
        status = process.memory().Read( moduleBase + tlsRva, sizeof( tlsDir ), &tlsDir );
        if (!NT_SUCCESS( status ))
            return status;

        if (tlsDir.AddressOfCallBacks == 0)
            return STATUS_SUCCESS;

        blackbone::ptr_t nullPtr = 0;
        return process.memory().Write( tlsDir.AddressOfCallBacks, sizeof( nullPtr ), &nullPtr );
    }

    static NTSTATUS InjectViaTLSCallback(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase,
        blackbone::ptr_t callbackAddress
        )
    {
        std::vector<uint8_t> headerBuffer( 0x1000 );

        NTSTATUS status = process.memory().Read( moduleBase, headerBuffer.size(), headerBuffer.data() );
        if (!NT_SUCCESS( status ))
            return status;

        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(headerBuffer.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return STATUS_INVALID_IMAGE_FORMAT;

        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(headerBuffer.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
            return STATUS_INVALID_IMAGE_FORMAT;

        DWORD tlsRva = 0;

#ifdef USE64
        if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            auto ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(ntHeaders);
            tlsRva = ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        }
#else
        if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            tlsRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        }
#endif

        if (tlsRva == 0)
            return STATUS_NOT_FOUND;

        IMAGE_TLS_DIRECTORY tlsDir = { 0 };
        status = process.memory().Read( moduleBase + tlsRva, sizeof( tlsDir ), &tlsDir );
        if (!NT_SUCCESS( status ))
            return status;

        if (tlsDir.AddressOfCallBacks == 0)
            return STATUS_NOT_FOUND;

        std::vector<blackbone::ptr_t> callbacks;
        blackbone::ptr_t currentAddr = tlsDir.AddressOfCallBacks;

        for (int i = 0; i < 64; i++)
        {
            blackbone::ptr_t callback = 0;
            status = process.memory().Read( currentAddr, sizeof( callback ), &callback );
            if (!NT_SUCCESS( status ) || callback == 0)
                break;

            callbacks.push_back( callback );
            currentAddr += sizeof( blackbone::ptr_t );
        }

        callbacks.insert( callbacks.begin(), callbackAddress );
        callbacks.push_back( 0 );

        auto callbackArray = process.memory().Allocate( callbacks.size() * sizeof( blackbone::ptr_t ), PAGE_READWRITE );
        if (!callbackArray)
            return STATUS_MEMORY_NOT_ALLOCATED;

        status = process.memory().Write( callbackArray->ptr(), callbacks.size() * sizeof( blackbone::ptr_t ), callbacks.data() );
        if (!NT_SUCCESS( status ))
            return status;

        blackbone::ptr_t newCallbackArrayAddr = callbackArray->ptr();
        return process.memory().Write( moduleBase + tlsRva + offsetof( IMAGE_TLS_DIRECTORY, AddressOfCallBacks ),
            sizeof( newCallbackArrayAddr ), &newCallbackArrayAddr );
    }

    static NTSTATUS GetTLSCallbacks(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase,
        std::vector<blackbone::ptr_t>& outCallbacks
        )
    {
        std::vector<uint8_t> headerBuffer( 0x1000 );

        NTSTATUS status = process.memory().Read( moduleBase, headerBuffer.size(), headerBuffer.data() );
        if (!NT_SUCCESS( status ))
            return status;

        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(headerBuffer.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return STATUS_INVALID_IMAGE_FORMAT;

        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(headerBuffer.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
            return STATUS_INVALID_IMAGE_FORMAT;

        DWORD tlsRva = 0;

#ifdef USE64
        if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            auto ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(ntHeaders);
            tlsRva = ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        }
#else
        if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            tlsRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        }
#endif

        if (tlsRva == 0)
            return STATUS_SUCCESS;

        IMAGE_TLS_DIRECTORY tlsDir = { 0 };
        status = process.memory().Read( moduleBase + tlsRva, sizeof( tlsDir ), &tlsDir );
        if (!NT_SUCCESS( status ))
            return status;

        if (tlsDir.AddressOfCallBacks == 0)
            return STATUS_SUCCESS;

        blackbone::ptr_t currentAddr = tlsDir.AddressOfCallBacks;

        for (int i = 0; i < 64; i++)
        {
            blackbone::ptr_t callback = 0;
            status = process.memory().Read( currentAddr, sizeof( callback ), &callback );
            if (!NT_SUCCESS( status ) || callback == 0)
                break;

            outCallbacks.push_back( callback );
            currentAddr += sizeof( blackbone::ptr_t );
        }

        return STATUS_SUCCESS;
    }
};
