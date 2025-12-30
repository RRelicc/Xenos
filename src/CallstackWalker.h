#pragma once

#include <Windows.h>
#include <vector>
#include <string>
#include <BlackBone/Process/Process.h>

class CallstackWalker
{
public:
    struct StackFrame
    {
        uint64_t returnAddress;
        std::wstring moduleName;
        std::wstring functionName;
        uint64_t offset;
    };

    static std::vector<StackFrame> WalkStack( blackbone::Process& process, HANDLE hThread )
    {
        std::vector<StackFrame> frames;

#ifdef _WIN64
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_FULL;

        if (!GetThreadContext( hThread, &ctx ))
            return frames;

        uint64_t rip = ctx.Rip;
        uint64_t rsp = ctx.Rsp;
        uint64_t rbp = ctx.Rbp;

        for (int i = 0; i < 64; i++)
        {
            StackFrame frame;
            frame.returnAddress = rip;

            auto mod = process.modules().GetModule( rip );
            if (mod)
            {
                frame.moduleName = mod->name;
                frame.offset = rip - mod->baseAddress;
            }

            frames.push_back( frame );

            if (rbp == 0)
                break;

            uint64_t nextRbp = 0;
            uint64_t nextRip = 0;

            if (!NT_SUCCESS( process.memory().Read( rbp, sizeof( nextRbp ), &nextRbp ) ))
                break;

            if (!NT_SUCCESS( process.memory().Read( rbp + 8, sizeof( nextRip ), &nextRip ) ))
                break;

            rip = nextRip;
            rbp = nextRbp;
        }
#endif

        return frames;
    }

    static bool IsReturnAddressValid( blackbone::Process& process, uint64_t returnAddress )
    {
        auto mod = process.modules().GetModule( returnAddress );
        return mod != nullptr;
    }

    static std::vector<uint64_t> GetValidReturnAddresses( blackbone::Process& process, size_t count )
    {
        std::vector<uint64_t> addresses;
        const auto& modules = process.modules().GetAllModules();

        for (const auto& modPair : modules)
        {
            if (addresses.size() >= count)
                break;

            addresses.push_back( modPair.second->baseAddress + 0x1000 );
        }

        return addresses;
    }
};
