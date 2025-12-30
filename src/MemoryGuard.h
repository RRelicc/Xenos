#pragma once

#include <Windows.h>

template<typename T = void>
class MemoryGuard
{
public:
    MemoryGuard() : _ptr(nullptr), _size(0) {}

    MemoryGuard(size_t size, DWORD protect = PAGE_EXECUTE_READWRITE)
        : _ptr(nullptr), _size(size)
    {
        _ptr = static_cast<T*>(VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, protect));
    }

    ~MemoryGuard()
    {
        if (_ptr)
        {
            VirtualFree(_ptr, 0, MEM_RELEASE);
            _ptr = nullptr;
        }
    }

    MemoryGuard(const MemoryGuard&) = delete;
    MemoryGuard& operator=(const MemoryGuard&) = delete;

    MemoryGuard(MemoryGuard&& other) noexcept
        : _ptr(other._ptr), _size(other._size)
    {
        other._ptr = nullptr;
        other._size = 0;
    }

    MemoryGuard& operator=(MemoryGuard&& other) noexcept
    {
        if (this != &other)
        {
            if (_ptr)
                VirtualFree(_ptr, 0, MEM_RELEASE);

            _ptr = other._ptr;
            _size = other._size;

            other._ptr = nullptr;
            other._size = 0;
        }
        return *this;
    }

    T* get() const { return _ptr; }
    operator bool() const { return _ptr != nullptr; }
    T* operator->() const { return _ptr; }

    size_t size() const { return _size; }

private:
    T* _ptr;
    size_t _size;
};
