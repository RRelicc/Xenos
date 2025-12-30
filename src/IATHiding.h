#pragma once

#include "Win11Compat.h"
#include <BlackBone/Process/Process.h>
#include <BlackBone/PE/PEImage.h>
#include <vector>
#include <string>

class IATHiding
{
public:
    struct IATEntry
    {
        std::string moduleName;
        std::string functionName;
        blackbone::ptr_t originalAddress = 0;
        blackbone::ptr_t hookedAddress = 0;
        blackbone::ptr_t iatEntryAddress = 0;
    };

    static NTSTATUS HideImport(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase,
        const std::string& moduleName,
        const std::string& functionName
        )
    {
        blackbone::pe::PEImage img;
        std::vector<uint8_t> buffer;

        auto mod = process.modules().GetModule( moduleBase );
        if (!mod)
            return STATUS_NOT_FOUND;

        buffer.resize( mod->size );

        if (!NT_SUCCESS( process.memory().Read( moduleBase, mod->size, buffer.data() ) ))
            return STATUS_MEMORY_NOT_ALLOCATED;

        if (img.Parse( buffer.data(), buffer.size(), true ) != STATUS_SUCCESS)
            return STATUS_INVALID_IMAGE_FORMAT;

        auto& imports = img.GetImports();

        for (const auto& import : imports)
        {
            if (_stricmp( blackbone::Utils::WstringToString( import.first ).c_str(), moduleName.c_str() ) == 0)
            {
                for (const auto& func : import.second)
                {
                    if (func.name == functionName)
                    {
                        blackbone::ptr_t iatEntry = moduleBase + func.ptrRVA;
                        blackbone::ptr_t nullPtr = 0;

                        return process.memory().Write( iatEntry, sizeof( nullPtr ), &nullPtr );
                    }
                }
            }
        }

        return STATUS_NOT_FOUND;
    }

    static NTSTATUS HideAllImports(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase
        )
    {
        blackbone::pe::PEImage img;
        std::vector<uint8_t> buffer;

        auto mod = process.modules().GetModule( moduleBase );
        if (!mod)
            return STATUS_NOT_FOUND;

        buffer.resize( mod->size );

        if (!NT_SUCCESS( process.memory().Read( moduleBase, mod->size, buffer.data() ) ))
            return STATUS_MEMORY_NOT_ALLOCATED;

        if (img.Parse( buffer.data(), buffer.size(), true ) != STATUS_SUCCESS)
            return STATUS_INVALID_IMAGE_FORMAT;

        auto& imports = img.GetImports();

        for (const auto& import : imports)
        {
            for (const auto& func : import.second)
            {
                blackbone::ptr_t iatEntry = moduleBase + func.ptrRVA;
                blackbone::ptr_t nullPtr = 0;

                process.memory().Write( iatEntry, sizeof( nullPtr ), &nullPtr );
            }
        }

        return STATUS_SUCCESS;
    }

    static NTSTATUS RedirectImport(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase,
        const std::string& moduleName,
        const std::string& functionName,
        blackbone::ptr_t newAddress
        )
    {
        blackbone::pe::PEImage img;
        std::vector<uint8_t> buffer;

        auto mod = process.modules().GetModule( moduleBase );
        if (!mod)
            return STATUS_NOT_FOUND;

        buffer.resize( mod->size );

        if (!NT_SUCCESS( process.memory().Read( moduleBase, mod->size, buffer.data() ) ))
            return STATUS_MEMORY_NOT_ALLOCATED;

        if (img.Parse( buffer.data(), buffer.size(), true ) != STATUS_SUCCESS)
            return STATUS_INVALID_IMAGE_FORMAT;

        auto& imports = img.GetImports();

        for (const auto& import : imports)
        {
            if (_stricmp( blackbone::Utils::WstringToString( import.first ).c_str(), moduleName.c_str() ) == 0)
            {
                for (const auto& func : import.second)
                {
                    if (func.name == functionName)
                    {
                        blackbone::ptr_t iatEntry = moduleBase + func.ptrRVA;

                        DWORD oldProtect = 0;
                        process.memory().Protect( iatEntry, sizeof( newAddress ), PAGE_READWRITE, &oldProtect );

                        NTSTATUS status = process.memory().Write( iatEntry, sizeof( newAddress ), &newAddress );

                        process.memory().Protect( iatEntry, sizeof( newAddress ), oldProtect, &oldProtect );

                        return status;
                    }
                }
            }
        }

        return STATUS_NOT_FOUND;
    }

    static std::vector<IATEntry> EnumerateIAT(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase
        )
    {
        std::vector<IATEntry> entries;

        blackbone::pe::PEImage img;
        std::vector<uint8_t> buffer;

        auto mod = process.modules().GetModule( moduleBase );
        if (!mod)
            return entries;

        if (!NT_SUCCESS( process.memory().Read( moduleBase, mod->size, buffer ) ))
            return entries;

        if (img.Parse( buffer.data(), buffer.size(), true ) != STATUS_SUCCESS)
            return entries;

        auto& imports = img.GetImports();

        for (const auto& import : imports)
        {
            for (const auto& func : import.second)
            {
                IATEntry entry;
                entry.moduleName = blackbone::Utils::WstringToString( import.first );
                entry.functionName = func.name;
                entry.iatEntryAddress = moduleBase + func.ptrRVA;

                blackbone::ptr_t addr = 0;
                if (NT_SUCCESS( process.memory().Read( entry.iatEntryAddress, sizeof( addr ), &addr ) ))
                {
                    entry.originalAddress = addr;
                }

                entries.push_back( entry );
            }
        }

        return entries;
    }

    static NTSTATUS RestoreIAT(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase
        )
    {
        blackbone::pe::PEImage localImg;
        std::vector<uint8_t> localBuffer;

        auto mod = process.modules().GetModule( moduleBase );
        if (!mod)
            return STATUS_NOT_FOUND;

        std::wstring modulePath = mod->fullPath;

        if (localImg.Load( modulePath ) != STATUS_SUCCESS)
            return STATUS_INVALID_IMAGE_FORMAT;

        auto& imports = localImg.GetImports();

        for (const auto& import : imports)
        {
            auto importMod = process.modules().GetModule( import.first );
            if (!importMod)
                continue;

            for (const auto& func : import.second)
            {
                auto exp = importMod->GetExport( func.name );
                if (!exp)
                    continue;

                blackbone::ptr_t iatEntry = moduleBase + func.ptrRVA;
                blackbone::ptr_t correctAddr = exp->procAddress;

                DWORD oldProtect = 0;
                process.memory().Protect( iatEntry, sizeof( correctAddr ), PAGE_READWRITE, &oldProtect );

                process.memory().Write( iatEntry, sizeof( correctAddr ), &correctAddr );

                process.memory().Protect( iatEntry, sizeof( correctAddr ), oldProtect, &oldProtect );
            }
        }

        return STATUS_SUCCESS;
    }

    static bool IsIATHooked(
        blackbone::Process& process,
        blackbone::ptr_t moduleBase,
        const std::string& moduleName,
        const std::string& functionName
        )
    {
        blackbone::pe::PEImage img;
        std::vector<uint8_t> buffer;

        auto mod = process.modules().GetModule( moduleBase );
        if (!mod)
            return false;

        if (!NT_SUCCESS( process.memory().Read( moduleBase, mod->size, buffer ) ))
            return false;

        if (img.Parse( buffer.data(), buffer.size(), true ) != STATUS_SUCCESS)
            return false;

        auto& imports = img.GetImports();

        for (const auto& import : imports)
        {
            if (_stricmp( blackbone::Utils::WstringToString( import.first ).c_str(), moduleName.c_str() ) == 0)
            {
                auto importMod = process.modules().GetModule( import.first );
                if (!importMod)
                    return false;

                for (const auto& func : import.second)
                {
                    if (func.name == functionName)
                    {
                        auto exp = importMod->GetExport( functionName );
                        if (!exp)
                            return false;

                        blackbone::ptr_t iatEntry = moduleBase + func.ptrRVA;
                        blackbone::ptr_t currentAddr = 0;

                        if (!NT_SUCCESS( process.memory().Read( iatEntry, sizeof( currentAddr ), &currentAddr ) ))
                            return false;

                        return currentAddr != exp->procAddress;
                    }
                }
            }
        }

        return false;
    }
};
