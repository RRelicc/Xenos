#pragma once

#include <Windows.h>
#include <winternl.h>
#include <string>

class Win11Compat
{
public:
    enum class WindowsVersion
    {
        Unknown = 0,
        Win7 = 1,
        Win8 = 2,
        Win8_1 = 3,
        Win10 = 4,
        Win11 = 5
    };

    struct SystemInfo
    {
        WindowsVersion version;
        DWORD buildNumber;
        bool isVBSEnabled;
        bool isHVCIEnabled;
        bool isCFGEnabled;
        bool isKernelCETEnabled;
        bool isTPMAvailable;
        bool isSecureBootEnabled;
        bool isWin11_22H2OrGreater;
        bool isWin11_23H2OrGreater;
        bool isCredentialGuardEnabled;
        bool isMemoryIntegrityEnabled;
    };

    static WindowsVersion GetWindowsVersion()
    {
        static WindowsVersion cachedVersion = WindowsVersion::Unknown;

        if (cachedVersion != WindowsVersion::Unknown)
            return cachedVersion;

        typedef NTSTATUS(NTAPI* pfnRtlGetVersion)(PRTL_OSVERSIONINFOW);

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll)
            return WindowsVersion::Unknown;

        auto pRtlGetVersion = reinterpret_cast<pfnRtlGetVersion>(
            GetProcAddress(hNtdll, "RtlGetVersion"));

        if (!pRtlGetVersion)
            return WindowsVersion::Unknown;

        RTL_OSVERSIONINFOW osvi = { 0 };
        osvi.dwOSVersionInfoSize = sizeof(osvi);

        if (pRtlGetVersion(&osvi) != 0)
            return WindowsVersion::Unknown;

        if (osvi.dwMajorVersion == 10 && osvi.dwMinorVersion == 0)
        {
            if (osvi.dwBuildNumber >= 22000)
                cachedVersion = WindowsVersion::Win11;
            else
                cachedVersion = WindowsVersion::Win10;
        }
        else if (osvi.dwMajorVersion == 6)
        {
            if (osvi.dwMinorVersion == 3)
                cachedVersion = WindowsVersion::Win8_1;
            else if (osvi.dwMinorVersion == 2)
                cachedVersion = WindowsVersion::Win8;
            else if (osvi.dwMinorVersion == 1)
                cachedVersion = WindowsVersion::Win7;
        }

        return cachedVersion;
    }

    static DWORD GetBuildNumber()
    {
        typedef NTSTATUS(NTAPI* pfnRtlGetVersion)(PRTL_OSVERSIONINFOW);

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll)
            return 0;

        auto pRtlGetVersion = reinterpret_cast<pfnRtlGetVersion>(
            GetProcAddress(hNtdll, "RtlGetVersion"));

        if (!pRtlGetVersion)
            return 0;

        RTL_OSVERSIONINFOW osvi = { 0 };
        osvi.dwOSVersionInfoSize = sizeof(osvi);

        if (pRtlGetVersion(&osvi) != 0)
            return 0;

        return osvi.dwBuildNumber;
    }

    static bool IsWindows11OrGreater()
    {
        return GetWindowsVersion() >= WindowsVersion::Win11;
    }

    static bool IsVBSEnabled()
    {
        HKEY hKey = nullptr;
        LONG result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
            0,
            KEY_READ,
            &hKey
        );

        if (result != ERROR_SUCCESS)
            return false;

        DWORD value = 0;
        DWORD size = sizeof(value);
        result = RegQueryValueExW(
            hKey,
            L"EnableVirtualizationBasedSecurity",
            nullptr,
            nullptr,
            reinterpret_cast<LPBYTE>(&value),
            &size
        );

        RegCloseKey(hKey);
        return (result == ERROR_SUCCESS && value == 1);
    }

    static bool IsHVCIEnabled()
    {
        HKEY hKey = nullptr;
        LONG result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
            0,
            KEY_READ,
            &hKey
        );

        if (result != ERROR_SUCCESS)
            return false;

        DWORD value = 0;
        DWORD size = sizeof(value);
        result = RegQueryValueExW(
            hKey,
            L"Enabled",
            nullptr,
            nullptr,
            reinterpret_cast<LPBYTE>(&value),
            &size
        );

        RegCloseKey(hKey);
        return (result == ERROR_SUCCESS && value == 1);
    }

    static bool IsCFGEnabled(HANDLE hProcess)
    {
        if (!hProcess)
            return false;

        typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
            HANDLE ProcessHandle,
            DWORD ProcessInformationClass,
            PVOID ProcessInformation,
            ULONG ProcessInformationLength,
            PULONG ReturnLength
        );

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll)
            return false;

        auto pNtQuery = reinterpret_cast<pfnNtQueryInformationProcess>(
            GetProcAddress(hNtdll, "NtQueryInformationProcess"));

        if (!pNtQuery)
            return false;

        const DWORD ProcessMitigationPolicy = 52;
        const DWORD ProcessControlFlowGuardPolicy = 7;

        struct PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY
        {
            union
            {
                DWORD Flags;
                struct
                {
                    DWORD EnableControlFlowGuard : 1;
                    DWORD EnableExportSuppression : 1;
                    DWORD StrictMode : 1;
                    DWORD Reserved : 29;
                };
            };
        };

        struct PROCESS_MITIGATION_POLICY_INFORMATION
        {
            DWORD Policy;
            union
            {
                PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY ControlFlowGuardPolicy;
            };
        };

        PROCESS_MITIGATION_POLICY_INFORMATION policyInfo = { 0 };
        policyInfo.Policy = ProcessControlFlowGuardPolicy;

        ULONG returnLength = 0;
        NTSTATUS status = pNtQuery(
            hProcess,
            ProcessMitigationPolicy,
            &policyInfo,
            sizeof(policyInfo),
            &returnLength
        );

        if (status != 0)
            return false;

        return policyInfo.ControlFlowGuardPolicy.EnableControlFlowGuard != 0;
    }

    static bool IsKernelCETEnabled()
    {
        HKEY hKey = nullptr;
        LONG result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel",
            0,
            KEY_READ,
            &hKey
        );

        if (result != ERROR_SUCCESS)
            return false;

        DWORD value = 0;
        DWORD size = sizeof(value);
        result = RegQueryValueExW(
            hKey,
            L"MitigationOptions",
            nullptr,
            nullptr,
            reinterpret_cast<LPBYTE>(&value),
            &size
        );

        RegCloseKey(hKey);

        if (result != ERROR_SUCCESS)
            return false;

        return (value & 0x00020000) != 0;
    }

    static bool IsCredentialGuardEnabled()
    {
        HKEY hKey = nullptr;
        LONG result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
            0,
            KEY_READ,
            &hKey
        );

        if (result != ERROR_SUCCESS)
            return false;

        DWORD value = 0;
        DWORD size = sizeof(value);
        result = RegQueryValueExW(
            hKey,
            L"EnableVirtualizationBasedSecurity",
            nullptr,
            nullptr,
            reinterpret_cast<LPBYTE>(&value),
            &size
        );

        bool vbsEnabled = (result == ERROR_SUCCESS && value == 1);

        if (!vbsEnabled)
        {
            RegCloseKey(hKey);
            return false;
        }

        result = RegQueryValueExW(
            hKey,
            L"RequirePlatformSecurityFeatures",
            nullptr,
            nullptr,
            reinterpret_cast<LPBYTE>(&value),
            &size
        );

        RegCloseKey(hKey);
        return (result == ERROR_SUCCESS && (value & 0x1));
    }

    static bool IsMemoryIntegrityEnabled()
    {
        return IsHVCIEnabled();
    }

    static bool IsWin11_22H2OrGreater()
    {
        DWORD build = GetBuildNumber();
        return build >= 22621;
    }

    static bool IsWin11_23H2OrGreater()
    {
        DWORD build = GetBuildNumber();
        return build >= 22631;
    }

    static bool IsProcessElevated()
    {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return false;

        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);

        if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size))
        {
            CloseHandle(hToken);
            return false;
        }

        CloseHandle(hToken);
        return elevation.TokenIsElevated != 0;
    }

    static bool HasSeDebugPrivilege()
    {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return false;

        LUID luid;
        if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid))
        {
            CloseHandle(hToken);
            return false;
        }

        PRIVILEGE_SET privs;
        privs.PrivilegeCount = 1;
        privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
        privs.Privilege[0].Luid = luid;
        privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

        BOOL result = FALSE;
        PrivilegeCheck(hToken, &privs, &result);

        CloseHandle(hToken);
        return result != FALSE;
    }

    static bool EnableSeDebugPrivilege()
    {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            return false;

        LUID luid;
        if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid))
        {
            CloseHandle(hToken);
            return false;
        }

        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);

        CloseHandle(hToken);
        return result != FALSE && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
    }

    static DWORD GetProcessMitigationFlags(HANDLE hProcess)
    {
        if (!hProcess)
            return 0;

        typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
            HANDLE ProcessHandle,
            DWORD ProcessInformationClass,
            PVOID ProcessInformation,
            ULONG ProcessInformationLength,
            PULONG ReturnLength
        );

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll)
            return 0;

        auto pNtQuery = reinterpret_cast<pfnNtQueryInformationProcess>(
            GetProcAddress(hNtdll, "NtQueryInformationProcess"));

        if (!pNtQuery)
            return 0;

        const DWORD ProcessMitigationPolicy = 52;
        DWORD flags = 0;

        for (DWORD policy = 0; policy < 20; policy++)
        {
            struct POLICY_INFO
            {
                DWORD Policy;
                DWORD Flags;
            };

            POLICY_INFO policyInfo = { policy, 0 };
            ULONG returnLength = 0;

            if (pNtQuery(hProcess, ProcessMitigationPolicy, &policyInfo, sizeof(policyInfo), &returnLength) == 0)
            {
                if (policyInfo.Flags)
                    flags |= (1 << policy);
            }
        }

        return flags;
    }

    static bool IsDEPEnabled(HANDLE hProcess)
    {
        if (!hProcess)
            return false;

        DWORD flags = 0;
        BOOL permanent = FALSE;

        if (!GetProcessDEPPolicy(hProcess, &flags, &permanent))
            return false;

        return (flags & PROCESS_DEP_ENABLE) != 0;
    }

    static bool IsASLREnabled(HANDLE hProcess)
    {
        typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
            HANDLE ProcessHandle,
            DWORD ProcessInformationClass,
            PVOID ProcessInformation,
            ULONG ProcessInformationLength,
            PULONG ReturnLength
        );

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll)
            return false;

        auto pNtQuery = reinterpret_cast<pfnNtQueryInformationProcess>(
            GetProcAddress(hNtdll, "NtQueryInformationProcess"));

        if (!pNtQuery)
            return false;

        const DWORD ProcessMitigationPolicy = 52;
        const DWORD ProcessASLRPolicy = 1;

        struct PROCESS_MITIGATION_ASLR_POLICY
        {
            union
            {
                DWORD Flags;
                struct
                {
                    DWORD EnableBottomUpRandomization : 1;
                    DWORD EnableForceRelocateImages : 1;
                    DWORD EnableHighEntropy : 1;
                    DWORD DisallowStrippedImages : 1;
                    DWORD Reserved : 28;
                };
            };
        };

        struct POLICY_INFO
        {
            DWORD Policy;
            union
            {
                PROCESS_MITIGATION_ASLR_POLICY ASLRPolicy;
            };
        };

        POLICY_INFO policyInfo = { ProcessASLRPolicy, 0 };
        ULONG returnLength = 0;

        if (pNtQuery(hProcess, ProcessMitigationPolicy, &policyInfo, sizeof(policyInfo), &returnLength) != 0)
            return false;

        return policyInfo.ASLRPolicy.EnableBottomUpRandomization != 0;
    }

    static bool IsTPMAvailable()
    {
        HKEY hKey = nullptr;
        LONG result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\TPM",
            0,
            KEY_READ,
            &hKey
        );

        if (result != ERROR_SUCCESS)
            return false;

        RegCloseKey(hKey);
        return true;
    }

    static bool IsSecureBootEnabled()
    {
        HKEY hKey = nullptr;
        LONG result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
            0,
            KEY_READ,
            &hKey
        );

        if (result != ERROR_SUCCESS)
            return false;

        DWORD value = 0;
        DWORD size = sizeof(value);
        result = RegQueryValueExW(
            hKey,
            L"UEFISecureBootEnabled",
            nullptr,
            nullptr,
            reinterpret_cast<LPBYTE>(&value),
            &size
        );

        RegCloseKey(hKey);
        return (result == ERROR_SUCCESS && value == 1);
    }

    static SystemInfo GetSystemInfo()
    {
        SystemInfo info;
        info.version = GetWindowsVersion();
        info.buildNumber = GetBuildNumber();
        info.isVBSEnabled = IsVBSEnabled();
        info.isHVCIEnabled = IsHVCIEnabled();
        info.isCFGEnabled = false;
        info.isKernelCETEnabled = IsKernelCETEnabled();
        info.isTPMAvailable = IsTPMAvailable();
        info.isSecureBootEnabled = IsSecureBootEnabled();
        info.isWin11_22H2OrGreater = IsWin11_22H2OrGreater();
        info.isWin11_23H2OrGreater = IsWin11_23H2OrGreater();
        info.isCredentialGuardEnabled = IsCredentialGuardEnabled();
        info.isMemoryIntegrityEnabled = IsMemoryIntegrityEnabled();
        return info;
    }

    static const wchar_t* GetVersionString(WindowsVersion version)
    {
        switch (version)
        {
        case WindowsVersion::Win11: return L"Windows 11";
        case WindowsVersion::Win10: return L"Windows 10";
        case WindowsVersion::Win8_1: return L"Windows 8.1";
        case WindowsVersion::Win8: return L"Windows 8";
        case WindowsVersion::Win7: return L"Windows 7";
        default: return L"Unknown";
        }
    }

    static bool SupportsKernelInjection()
    {
        auto info = GetSystemInfo();

        if (info.isHVCIEnabled || info.isKernelCETEnabled)
            return false;

        return true;
    }

    static bool RequiresEnhancedEvasion()
    {
        auto info = GetSystemInfo();
        return info.version >= WindowsVersion::Win11 ||
               info.isVBSEnabled ||
               info.isHVCIEnabled;
    }

    static bool CanInjectIntoProcess(HANDLE hProcess)
    {
        if (!hProcess)
            return false;

        if (!IsProcessElevated())
            return false;

        if (!HasSeDebugPrivilege())
            return false;

        if (IsHVCIEnabled() && IsVBSEnabled())
            return false;

        return true;
    }

    static DWORD GetRecommendedInjectionMethod()
    {
        auto info = GetSystemInfo();

        if (info.isHVCIEnabled || info.isKernelCETEnabled)
            return 1;

        if (info.isVBSEnabled)
            return 1;

        if (info.version >= WindowsVersion::Win11)
            return 1;

        return 0;
    }

    static std::wstring GetSecuritySummary()
    {
        auto info = GetSystemInfo();
        std::wstring summary = L"Security Features:\n";

        summary += L"  OS: " + std::wstring(GetVersionString(info.version)) +
                   L" (Build " + std::to_wstring(info.buildNumber) + L")\n";

        if (info.isVBSEnabled)
            summary += L"  [!] VBS Enabled\n";

        if (info.isHVCIEnabled)
            summary += L"  [!] HVCI/Memory Integrity Enabled\n";

        if (info.isKernelCETEnabled)
            summary += L"  [!] Kernel CET Enabled\n";

        if (info.isCredentialGuardEnabled)
            summary += L"  [!] Credential Guard Enabled\n";

        if (info.isSecureBootEnabled)
            summary += L"  [!] Secure Boot Enabled\n";

        if (info.isTPMAvailable)
            summary += L"  [+] TPM Available\n";

        if (!IsProcessElevated())
            summary += L"  [!] Not running as Administrator\n";

        if (!HasSeDebugPrivilege())
            summary += L"  [!] SeDebugPrivilege not available\n";

        return summary;
    }

    static bool IsHardenedProcess(HANDLE hProcess)
    {
        if (!hProcess)
            return false;

        bool hasCFG = IsCFGEnabled(hProcess);
        bool hasDEP = IsDEPEnabled(hProcess);
        bool hasASLR = IsASLREnabled(hProcess);

        return hasCFG || (hasDEP && hasASLR);
    }
};
