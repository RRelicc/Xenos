#pragma once

#include "Win11Compat.h"
#include <type_traits>
#include <utility>
#include <string>

template<typename T>
class Result
{
public:
    Result( NTSTATUS status ) : _status( status ), _hasValue( false ) {}

    Result( T&& value ) : _status( STATUS_SUCCESS ), _value( std::forward<T>( value ) ), _hasValue( true ) {}

    Result( const T& value ) : _status( STATUS_SUCCESS ), _value( value ), _hasValue( true ) {}

    Result( NTSTATUS status, T&& value ) : _status( status ), _value( std::forward<T>( value ) ), _hasValue( true ) {}

    ~Result() = default;

    Result( const Result& ) = default;
    Result& operator=( const Result& ) = default;

    Result( Result&& other ) noexcept
        : _status( other._status )
        , _value( std::move( other._value ) )
        , _hasValue( other._hasValue )
    {
        other._hasValue = false;
    }

    Result& operator=( Result&& other ) noexcept
    {
        if (this != &other)
        {
            _status = other._status;
            _value = std::move( other._value );
            _hasValue = other._hasValue;
            other._hasValue = false;
        }
        return *this;
    }

    bool IsSuccess() const { return NT_SUCCESS( _status ); }
    bool HasValue() const { return _hasValue; }

    NTSTATUS Status() const { return _status; }

    T& Value() { return _value; }
    const T& Value() const { return _value; }

    T ValueOr( T&& defaultValue ) const
    {
        return _hasValue ? _value : std::forward<T>( defaultValue );
    }

    T* operator->() { return &_value; }
    const T* operator->() const { return &_value; }

    T& operator*() { return _value; }
    const T& operator*() const { return _value; }

    explicit operator bool() const { return IsSuccess() && _hasValue; }

private:
    NTSTATUS _status;
    T _value;
    bool _hasValue;
};

template<>
class Result<void>
{
public:
    explicit Result( NTSTATUS status = STATUS_SUCCESS ) : _status( status ) {}

    bool IsSuccess() const { return NT_SUCCESS( _status ); }
    NTSTATUS Status() const { return _status; }

    explicit operator bool() const { return IsSuccess(); }

private:
    NTSTATUS _status;
};
