Xenos
=====

Windows dll injector. Based on Blackbone library - https://github.com/DarthTon/Blackbone

## Features ##

- Supports x86 and x64 processes and modules
- Kernel-mode injection feature (driver required)
- Manual map of kernel drivers (driver required)
- Injection of pure managed images without proxy dll
- Windows 7 cross-session and cross-desktop injection
- Injection into native processes (those having only ntdll loaded)
- Calling custom initialization routine after injection
- Unlinking module after injection
- Injection using thread hijacking
- Injection of x64 images into WOW64 process
- Image manual mapping
- Injection profiles

Manual map features:
- Relocations, import, delayed import, bound import
- Hiding allocated image memory (driver required)
- Static TLS and TLS callbacks
- Security cookie
- Image manifests and SxS
- Make module visible to GetModuleHandle, GetProcAddress, etc.
- Support for exceptions in private memory under DEP
- C++/CLI images are supported (use 'Add loader reference' in this case)

Windows 11 features:
- VBS (Virtualization Based Security) detection
- HVCI (Hypervisor-protected Code Integrity) detection
- CFG (Control Flow Guard) aware injection
- Automatic security feature detection and adjustment
- Optimized memory allocation for Windows 11
- Enhanced evasion techniques for modern security

Extended functionality:
- Smart process attachment with automatic access rights
- Pattern search across modules and memory regions
- Kernel driver management with safety checks
- Local hook installation and tracking
- Memory scanning and code cave detection
- Module validation and signature verification
- Retry logic for stability on protected processes
- Performance monitoring and error reporting

Stealth and evasion:
- IAT (Import Address Table) hiding and redirection
- PEB manipulation to hide modules and spoof process information
- Call stack spoofing with ROP gadgets
- Heaven's Gate technique for WoW64 syscalls
- PE header wiping after injection
- Memory artifact cleaning and pattern removal
- DKOM (Direct Kernel Object Manipulation) via driver
- Process ghosting injection for Windows 10/11
- TLS callback manipulation and spoofing
- Thread name spoofing with legitimate names

Security and modern C++:
- RAII wrappers for automatic resource management (HandleGuard, MemoryGuard)
- Result<T> type for unified error handling
- Cryptographically secure random generation (BCryptGenRandom)
- Buffer overflow protection and bounds checking
- Smart pointers (std::unique_ptr) replacing manual memory management
- Optimized data structures (std::unordered_set for O(1) lookups)
- Chunked pattern search for large modules (50MB+ support)

Supported OS: Win7 - Win11 x64

## License ##
Xenos is licensed under the MIT License. Dependencies are under their respective licenses.

[![Build status](https://ci.appveyor.com/api/projects/status/eu6lpbla89gjgy5m?svg=true)](https://ci.appveyor.com/project/DarthTon/xenos)