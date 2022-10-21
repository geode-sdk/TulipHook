#pragma once

#include <string_view>
#include <string>
#include <variant>

namespace tulip::hook {
    struct AnyType {
        explicit AnyType() = delete;
    };

    template<class V, class RV>
    concept ConvertibleToResult =
        std::is_convertible_v<
            std::remove_reference_t<V>,
            std::remove_reference_t<RV>
        > || std::is_same_v<
            std::remove_reference_t<V>,
            std::remove_reference_t<RV>
        >;
    
    using DefaultValue = std::monostate;
    using DefaultError = std::string;

    template<class T = DefaultValue, class E = DefaultError>
        requires (
            std::is_copy_constructible_v<T> || 
            std::is_move_constructible_v<T>
        ) && (
            std::is_copy_constructible_v<E> || 
            std::is_move_constructible_v<E>
        )
    class [[nodiscard]] Result {
    public:
        using value_type = std::remove_reference_t<T>;
        using error_type = std::remove_reference_t<E>;

    protected:
        std::variant<value_type, error_type> m_value;
    
    public:
        bool isOk() const {
            return std::holds_alternative<value_type>(m_value);
        }

        bool isErr() const {
            return std::holds_alternative<error_type>(m_value);
        }

        explicit Result(value_type const& value)
            requires std::is_copy_constructible_v<value_type>
          : m_value(value) {}
        explicit Result(value_type&& value)
            requires std::is_move_constructible_v<value_type>
          : m_value(std::forward<value_type>(value)) {}

        explicit Result(error_type const& value)
            requires std::is_copy_constructible_v<error_type>
          : m_value(value) {}
        explicit Result(error_type&& value)
            requires std::is_move_constructible_v<error_type>
          : m_value(std::forward<error_type>(value)) {}
        
        Result(Result<T, E> const& other)
            requires
                std::is_copy_constructible_v<value_type> &&
                std::is_copy_constructible_v<error_type>
          = default;
        
        Result(Result<T, E>&& other)
            requires (
                !std::is_copy_constructible_v<value_type> ||
                !std::is_copy_constructible_v<error_type>
            ) = default;
        
        template<class T2, class E2>
            requires ConvertibleToResult<T2, T> && ConvertibleToResult<E2, E>
        Result(Result<T2, E2> const& other)
            requires
                std::is_copy_constructible_v<value_type> &&
                std::is_copy_constructible_v<error_type>
          : m_value(other.isOk() ? other.unwrap() : other.unwrapErr()) {}
        
        template<class T2, class E2>
            requires ConvertibleToResult<T2, T> && ConvertibleToResult<E2, E>
        Result(Result<T2, E2>&& other)
            requires (
                !std::is_copy_constructible_v<value_type> ||
                !std::is_copy_constructible_v<error_type>
            ) : m_value(other.isOk() ? other.unwrap() : other.unwrapErr()) {}
        
        template<class T2>
            requires ConvertibleToResult<T2, T>
        Result(Result<T2, AnyType> const& other)
            requires
                std::is_copy_constructible_v<value_type> &&
                std::is_copy_constructible_v<error_type>
          : Result(value_type(other.unwrap())) {}
        
        template<class E2>
            requires ConvertibleToResult<E2, E>
        Result(Result<AnyType, E2> const& other)
            requires
                std::is_copy_constructible_v<value_type> &&
                std::is_copy_constructible_v<error_type>
          : m_value(std::forward<E2>(other.unwrapErr())) {}
        
        template<class T2>
            requires ConvertibleToResult<T2, T>
        Result(Result<T2, AnyType>&& other)
            requires (
                !std::is_copy_constructible_v<value_type> ||
                !std::is_copy_constructible_v<error_type>
            ) : m_value(other.unwrap()) {}
        
        template<class E2>
            requires ConvertibleToResult<E2, E>
        Result(Result<AnyType, E2>&& other)
            requires (
                !std::is_copy_constructible_v<value_type> ||
                !std::is_copy_constructible_v<error_type>
            ) : Result(std::forward<error_type>(other.unwrapErr())) {}

        value_type unwrap() const
            requires std::is_copy_constructible_v<value_type>
        {
            return std::get<value_type>(m_value);
        }

        value_type&& unwrap()
            requires (!std::is_copy_constructible_v<value_type>)
        {
            return std::move(std::get<value_type>(m_value));
        }

        error_type unwrapErr() const
            requires std::is_copy_constructible_v<error_type>
        {
            return std::get<error_type>(m_value);
        }

        error_type&& unwrapErr()
            requires (!std::is_copy_constructible_v<error_type>)
        {
            return std::get<error_type>(m_value);
        }

        // no operator bool as if bool is convertible to value, doing 
        // T = Result<T> will cause unexpected behaviour
    };

    template<class T = DefaultValue, class E = AnyType>
        requires std::is_copy_constructible_v<T>
    Result<T, E> Ok(T value = T()) {
        return Result<T, E>(value);
    }

    template<class T = DefaultValue, class E = AnyType>
        requires (!std::is_copy_constructible_v<T>)
    Result<T, E> Ok(T&& value) {
        return Result<T, E>(std::forward<T>(value));
    }

    template<class E = DefaultError, class T = AnyType>
        requires std::is_copy_constructible_v<E>
    Result<T, E> Err(E error = E()) {
        return Result<T, E>(error);
    }

    template<class E = DefaultError, class T = AnyType>
        requires (!std::is_copy_constructible_v<E>)
    Result<T, E> Err(E&& error) {
        return Result<T, E>(std::forward<E>(error));
    }

    #define TULIP_CONCAT_(a, b) a ## b
    #define TULIP_CONCAT(a, b) TULIP_CONCAT_(a, b)

    #define TULIP_UNWRAP_INTO(into, ...) \
        auto TULIP_CONCAT(res_, __LINE__) = (__VA_ARGS__);\
        if (TULIP_CONCAT(res_, __LINE__).isErr()) {\
            return Err(std::move(TULIP_CONCAT(res_, __LINE__).unwrapErr()));\
        }\
        into = std::move(TULIP_CONCAT(res_, __LINE__).unwrap())

    #define TULIP_UNWRAP(...) \
        { auto TULIP_CONCAT(res_, __LINE__) = (__VA_ARGS__);\
        if (TULIP_CONCAT(res_, __LINE__).isErr()) {\
            return Err(std::move(TULIP_CONCAT(res_, __LINE__).unwrapErr()));\
        } }
}
