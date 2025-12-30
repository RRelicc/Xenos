#pragma once

#include "Win11Compat.h"
#include <BlackBone/Patterns/PatternSearch.h>
#include <BlackBone/Process/Process.h>
#include <vector>
#include <string>

class PatternSearchEx
{
public:
    struct SearchResult
    {
        blackbone::ptr_t address = 0;
        size_t offset = 0;
        std::wstring moduleName;
        bool valid = false;
    };

    static std::vector<SearchResult> SearchInModule(
        blackbone::Process& process,
        const std::wstring& moduleName,
        const std::string& pattern,
        bool firstOnly = false
        )
    {
        std::vector<SearchResult> results;

        auto mod = process.modules().GetModule( moduleName );
        if (!mod)
            return results;

        const size_t maxChunkSize = 50 * 1024 * 1024;

        blackbone::PatternSearch searcher( pattern );
        std::vector<blackbone::ptr_t> found;

        if (mod->size > maxChunkSize)
        {
            size_t offset = 0;
            while (offset < mod->size)
            {
                size_t chunkSize = (std::min)( maxChunkSize, mod->size - offset );

                searcher.SearchRemote( process, pattern, mod->baseAddress + offset, chunkSize, found, firstOnly ? 1 : 0 );

                if (firstOnly && !found.empty())
                    break;

                offset += chunkSize;
            }
        }
        else
        {
            process.memory().Read( mod->baseAddress, mod->size, _buffer );
            searcher.SearchRemote( process, pattern, mod->baseAddress, mod->size, found, firstOnly ? 1 : 0 );
        }

        for (const auto& addr : found)
        {
            SearchResult result;
            result.address = addr;
            result.offset = addr - mod->baseAddress;
            result.moduleName = moduleName;
            result.valid = true;
            results.emplace_back( result );
        }

        return results;
    }

    static std::vector<SearchResult> SearchInAllModules(
        blackbone::Process& process,
        const std::string& pattern
        )
    {
        std::vector<SearchResult> results;
        auto modules = process.modules().GetAllModules();

        for (const auto& mod : modules)
        {
            auto moduleResults = SearchInModule( process, mod.second->name, pattern, false );
            results.insert( results.end(), moduleResults.begin(), moduleResults.end() );
        }

        return results;
    }

    static SearchResult SearchInRange(
        blackbone::Process& process,
        const std::string& pattern,
        blackbone::ptr_t startAddress,
        size_t size
        )
    {
        SearchResult result;

        blackbone::PatternSearch searcher( pattern );
        std::vector<blackbone::ptr_t> found;

        searcher.SearchRemote( process, pattern, startAddress, size, found, 1 );

        if (!found.empty())
        {
            result.address = found[0];
            result.offset = found[0] - startAddress;
            result.valid = true;
        }

        return result;
    }

    static std::vector<SearchResult> SearchBySignature(
        blackbone::Process& process,
        const std::wstring& moduleName,
        const std::vector<uint8_t>& signature,
        const std::vector<bool>& mask
        )
    {
        std::vector<SearchResult> results;

        auto mod = process.modules().GetModule( moduleName );
        if (!mod)
            return results;

        std::vector<uint8_t> buffer( mod->size );
        if (NT_SUCCESS( process.memory().Read( mod->baseAddress, mod->size, buffer.data() ) ))
        {
            if (buffer.size() < signature.size())
                return results;

            for (size_t i = 0; i <= buffer.size() - signature.size(); ++i)
            {
                bool found = true;
                for (size_t j = 0; j < signature.size(); ++j)
                {
                    if (mask[j] && buffer[i + j] != signature[j])
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    SearchResult result;
                    result.address = mod->baseAddress + i;
                    result.offset = i;
                    result.moduleName = moduleName;
                    result.valid = true;
                    results.push_back( result );
                }
            }
        }

        return results;
    }

    static SearchResult FindFunctionStart(
        blackbone::Process& process,
        blackbone::ptr_t address
        )
    {
        SearchResult result;

        uint8_t buffer[256] = { 0 };
        if (!NT_SUCCESS( process.memory().Read( address - 128, 256, buffer ) ))
            return result;

        for (int i = 127; i >= 0; --i)
        {
            if ((buffer[i] == 0x55 && buffer[i + 1] == 0x8B) ||
                (buffer[i] == 0x48 && buffer[i + 1] == 0x89) ||
                (buffer[i] == 0x40 && buffer[i + 1] == 0x53))
            {
                result.address = address - 128 + i;
                result.offset = i;
                result.valid = true;
                break;
            }
        }

        return result;
    }

    static std::vector<blackbone::ptr_t> FindAllReferences(
        blackbone::Process& process,
        const std::wstring& moduleName,
        blackbone::ptr_t targetAddress
        )
    {
        std::vector<blackbone::ptr_t> references;

        auto mod = process.modules().GetModule( moduleName );
        if (!mod)
            return references;

        std::vector<uint8_t> buffer( mod->size );
        if (!NT_SUCCESS( process.memory().Read( mod->baseAddress, mod->size, buffer.data() ) ))
            return references;

        blackbone::ptr_t* ptrBuffer = reinterpret_cast<blackbone::ptr_t*>(buffer.data());
        size_t ptrCount = buffer.size() / sizeof( blackbone::ptr_t );

        for (size_t i = 0; i < ptrCount; ++i)
        {
            if (ptrBuffer[i] == targetAddress)
            {
                references.push_back( mod->baseAddress + i * sizeof( blackbone::ptr_t ) );
            }
        }

        return references;
    }

    static bool ValidatePattern( const std::string& pattern )
    {
        try
        {
            blackbone::PatternSearch searcher( pattern );
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

private:
    static thread_local std::vector<uint8_t> _buffer;
};

thread_local std::vector<uint8_t> PatternSearchEx::_buffer;
