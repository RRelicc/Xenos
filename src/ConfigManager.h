#pragma once

#include "Win11Compat.h"
#include <string>
#include <map>
#include <fstream>

class ConfigManager
{
public:
    struct InjectionSettings
    {
        bool autoElevate = true;
        bool detectVBS = true;
        bool detectHVCI = true;
        bool detectCFG = true;
        bool autoRetry = true;
        int maxRetries = 5;
        int retryDelay = 200;
        bool logInjections = true;
        bool enableMonitoring = true;
        bool validatePE = true;
        bool checkCompatibility = true;
    };

    static InjectionSettings& GetSettings()
    {
        return _settings;
    }

    static void LoadSettings( const std::wstring& configPath )
    {
        std::wifstream file( configPath );
        if (!file.is_open())
            return;

        std::wstring line;
        while (std::getline( file, line ))
        {
            size_t pos = line.find( L'=' );
            if (pos == std::wstring::npos)
                continue;

            std::wstring key = line.substr( 0, pos );
            std::wstring value = line.substr( pos + 1 );

            Trim( key );
            Trim( value );

            SetValue( key, value );
        }

        file.close();
    }

    static void SaveSettings( const std::wstring& configPath )
    {
        std::wofstream file( configPath );
        if (!file.is_open())
            return;

        file << L"autoElevate=" << _settings.autoElevate << L"\n";
        file << L"detectVBS=" << _settings.detectVBS << L"\n";
        file << L"detectHVCI=" << _settings.detectHVCI << L"\n";
        file << L"detectCFG=" << _settings.detectCFG << L"\n";
        file << L"autoRetry=" << _settings.autoRetry << L"\n";
        file << L"maxRetries=" << _settings.maxRetries << L"\n";
        file << L"retryDelay=" << _settings.retryDelay << L"\n";
        file << L"logInjections=" << _settings.logInjections << L"\n";
        file << L"enableMonitoring=" << _settings.enableMonitoring << L"\n";
        file << L"validatePE=" << _settings.validatePE << L"\n";
        file << L"checkCompatibility=" << _settings.checkCompatibility << L"\n";

        file.close();
    }

    static void ResetToDefaults()
    {
        _settings = InjectionSettings();

        if (Win11Compat::IsWindows11OrGreater())
        {
            _settings.maxRetries = 5;
            _settings.retryDelay = 200;
        }
        else
        {
            _settings.maxRetries = 3;
            _settings.retryDelay = 100;
        }
    }

    static void ApplyWindowsOptimizations()
    {
        if (Win11Compat::IsWindows11OrGreater())
        {
            _settings.detectVBS = true;
            _settings.detectHVCI = true;
            _settings.detectCFG = true;
            _settings.maxRetries = 5;
            _settings.retryDelay = 200;
        }

        if (Win11Compat::IsVBSEnabled())
        {
            _settings.autoElevate = false;
        }

        if (Win11Compat::IsHVCIEnabled())
        {
            _settings.validatePE = true;
            _settings.checkCompatibility = true;
        }
    }

private:
    static void SetValue( const std::wstring& key, const std::wstring& value )
    {
        if (key == L"autoElevate")
            _settings.autoElevate = (value == L"1" || value == L"true");
        else if (key == L"detectVBS")
            _settings.detectVBS = (value == L"1" || value == L"true");
        else if (key == L"detectHVCI")
            _settings.detectHVCI = (value == L"1" || value == L"true");
        else if (key == L"detectCFG")
            _settings.detectCFG = (value == L"1" || value == L"true");
        else if (key == L"autoRetry")
            _settings.autoRetry = (value == L"1" || value == L"true");
        else if (key == L"maxRetries")
            _settings.maxRetries = std::stoi( value );
        else if (key == L"retryDelay")
            _settings.retryDelay = std::stoi( value );
        else if (key == L"logInjections")
            _settings.logInjections = (value == L"1" || value == L"true");
        else if (key == L"enableMonitoring")
            _settings.enableMonitoring = (value == L"1" || value == L"true");
        else if (key == L"validatePE")
            _settings.validatePE = (value == L"1" || value == L"true");
        else if (key == L"checkCompatibility")
            _settings.checkCompatibility = (value == L"1" || value == L"true");
    }

    static void Trim( std::wstring& str )
    {
        size_t start = str.find_first_not_of( L" \t\r\n" );
        size_t end = str.find_last_not_of( L" \t\r\n" );

        if (start == std::wstring::npos || end == std::wstring::npos)
        {
            str.clear();
            return;
        }

        str = str.substr( start, end - start + 1 );
    }

    static InjectionSettings _settings;
};

ConfigManager::InjectionSettings ConfigManager::_settings;
