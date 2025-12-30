#pragma once

#include <Windows.h>
#include <utility>

template<typename HandleType = HANDLE, HandleType InvalidValue = nullptr>
class HandleGuard
{
public:
    HandleGuard() noexcept : _handle( InvalidValue ) {}

    explicit HandleGuard( HandleType handle ) noexcept : _handle( handle ) {}

    ~HandleGuard() noexcept
    {
        Close();
    }

    HandleGuard( const HandleGuard& ) = delete;
    HandleGuard& operator=( const HandleGuard& ) = delete;

    HandleGuard( HandleGuard&& other ) noexcept : _handle( other._handle )
    {
        other._handle = InvalidValue;
    }

    HandleGuard& operator=( HandleGuard&& other ) noexcept
    {
        if (this != &other)
        {
            Close();
            _handle = other._handle;
            other._handle = InvalidValue;
        }
        return *this;
    }

    void Close() noexcept
    {
        if (_handle != InvalidValue)
        {
            CloseHandle( _handle );
            _handle = InvalidValue;
        }
    }

    HandleType Release() noexcept
    {
        HandleType temp = _handle;
        _handle = InvalidValue;
        return temp;
    }

    void Reset( HandleType handle = InvalidValue ) noexcept
    {
        Close();
        _handle = handle;
    }

    HandleType Get() const noexcept
    {
        return _handle;
    }

    explicit operator bool() const noexcept
    {
        return _handle != InvalidValue;
    }

    HandleType* operator&() noexcept
    {
        return &_handle;
    }

private:
    HandleType _handle;
};

using FileHandle = HandleGuard<HANDLE, INVALID_HANDLE_VALUE>;
using ProcessHandle = HandleGuard<HANDLE, nullptr>;
using ThreadHandle = HandleGuard<HANDLE, nullptr>;
using TokenHandle = HandleGuard<HANDLE, nullptr>;

class RegistryKeyGuard
{
public:
    RegistryKeyGuard() noexcept : _hKey( nullptr ) {}

    explicit RegistryKeyGuard( HKEY hKey ) noexcept : _hKey( hKey ) {}

    ~RegistryKeyGuard() noexcept
    {
        Close();
    }

    RegistryKeyGuard( const RegistryKeyGuard& ) = delete;
    RegistryKeyGuard& operator=( const RegistryKeyGuard& ) = delete;

    RegistryKeyGuard( RegistryKeyGuard&& other ) noexcept : _hKey( other._hKey )
    {
        other._hKey = nullptr;
    }

    RegistryKeyGuard& operator=( RegistryKeyGuard&& other ) noexcept
    {
        if (this != &other)
        {
            Close();
            _hKey = other._hKey;
            other._hKey = nullptr;
        }
        return *this;
    }

    void Close() noexcept
    {
        if (_hKey)
        {
            RegCloseKey( _hKey );
            _hKey = nullptr;
        }
    }

    HKEY Release() noexcept
    {
        HKEY temp = _hKey;
        _hKey = nullptr;
        return temp;
    }

    void Reset( HKEY hKey = nullptr ) noexcept
    {
        Close();
        _hKey = hKey;
    }

    HKEY Get() const noexcept
    {
        return _hKey;
    }

    explicit operator bool() const noexcept
    {
        return _hKey != nullptr;
    }

    HKEY* operator&() noexcept
    {
        return &_hKey;
    }

private:
    HKEY _hKey;
};
