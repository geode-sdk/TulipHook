#pragma once

// this is worse than i initially thought
// really worse
// im just doing this to get rid of weak link warnings
#ifndef TULIP_HOOK_RESULT_RESULT
#define TULIP_HOOK_RESULT_RESULT

#ifdef RESULT_RESULT_HPP
	#undef RESULT_RESULT_HPP
	#define TULIP_HOOK_RESULT_RESULT_DEFINED
#endif

#pragma push_macro("RESULT_NAMESPACE")

#define RESULT_NAMESPACE tulip::hook::lib
#include "../../lib/result/include/result.hpp"

#pragma pop_macro("RESULT_NAMESPACE")

#ifdef TULIP_HOOK_RESULT_RESULT_DEFINED
	#undef TULIP_HOOK_RESULT_RESULT_DEFINED
	#define RESULT_RESULT_HPP
#endif

#endif

#include <string>
#include <string_view>
#include <variant>

namespace tulip::hook {

	namespace impl {
		using DefaultValue = std::monostate;
		using DefaultError = std::string;
		template <class T>
		using WrappedResult = std::conditional_t<
			std::is_lvalue_reference_v<T>, std::reference_wrapper<std::remove_reference_t<T>>, std::remove_const_t<T>>;

		template <class E = impl::DefaultError>
		class [[nodiscard]] Failure {
		public:
			WrappedResult<E> m_error;

			Failure() = default;

			template <class E2>
				requires(std::is_constructible_v<E, E2 const&>)
			explicit constexpr Failure(E2 const& e) :
				m_error(e) {}

			template <class E2>
				requires(std::is_constructible_v<E, E2 &&>)
			explicit constexpr Failure(E2&& e) :
				m_error(std::move(e)) {}

			E& error() & noexcept {
				return m_error;
			}

			E const& error() const& noexcept {
				return m_error;
			}

			E&& error() && noexcept {
				return static_cast<E&&>(m_error);
			}

			E const&& error() const&& noexcept {
				return static_cast<E&&>(m_error);
			}
		};

		template <class T = impl::DefaultValue>
		class [[nodiscard]] Success {
		public:
			WrappedResult<T> m_value;

			Success() = default;

			template <class T2>
				requires(std::is_constructible_v<T, T2 const&>)
			explicit constexpr Success(T2 const& v) :
				m_value(v) {}

			template <class T2>
				requires(std::is_constructible_v<T, T2 &&>)
			explicit constexpr Success(T2&& v) :
				m_value(std::forward<T2>(v)) {}

			T& value() & noexcept {
				return m_value;
			}

			T const& value() const& noexcept {
				return m_value;
			}

			T&& value() && noexcept {
				return static_cast<T&&>(m_value);
			}

			T const&& value() const&& noexcept {
				return static_cast<T&&>(m_value);
			}
		};
	}

	template <class T = impl::DefaultValue, class E = impl::DefaultError>
	class [[nodiscard]] Result : public lib::result<T, E> {
	public:
		using Base = lib::result<T, E>;
		using ValueType = typename Base::value_type;
		using ErrorType = typename Base::error_type;

		using Base::result;

		template <class U>
			requires(lib::detail::result_is_implicit_value_convertible<T, U>::value)
		constexpr Result(U&& value) = delete;

		template <class E2>
			requires(std::is_constructible_v<E, E2 const&>)
		constexpr Result(impl::Failure<E2> const& e) :
			Base(lib::failure<E>(e.error())) {}

		template <class E2>
			requires(std::is_constructible_v<E, E2 &&>)
		constexpr Result(impl::Failure<E2>&& e) :
			Base(lib::failure<E>(std::move(e.error()))) {}

		template <class T2>
			requires(std::is_constructible_v<T, T2 const&>)
		constexpr Result(impl::Success<T2> const& s) :
			Base(s.value()) {}

		template <class T2>
			requires(std::is_constructible_v<T, T2 &&>)
		constexpr Result(impl::Success<T2>&& s) :
			Base(std::move(s.value())) {}

		[[nodiscard]] constexpr explicit operator bool() const noexcept {
			return Base::operator bool();
		}

		[[nodiscard]] constexpr bool isOk() const noexcept {
			return this->has_value();
		}

		[[nodiscard]] constexpr bool isErr() const noexcept {
			return this->has_error();
		}

		[[nodiscard]] constexpr decltype(auto) unwrap() & {
			return this->value();
		}

		[[nodiscard]] constexpr decltype(auto) unwrap() const& {
			return this->value();
		}

		[[nodiscard]] constexpr decltype(auto) unwrap() && {
			return this->value();
		}

		[[nodiscard]] constexpr decltype(auto) unwrap() const&& {
			return this->value();
		}

		[[nodiscard]] constexpr decltype(auto) unwrapErr() & {
			return this->error();
		}

		[[nodiscard]] constexpr decltype(auto) unwrapErr() const& {
			return this->error();
		}

		[[nodiscard]] constexpr decltype(auto) unwrapErr() && {
			return this->error();
		}

		[[nodiscard]] constexpr decltype(auto) unwrapErr() const&& {
			return this->error();
		}

		template <class U>
		[[nodiscard]] constexpr decltype(auto) unwrapOr(U&& val) && {
			return this->value_or(std::forward<U>(val));
		}

		template <class U>
		[[nodiscard]] constexpr decltype(auto) unwrapOr(U&& val) const& {
			return this->value_or(std::forward<U>(val));
		}

		template <class U>
		[[nodiscard]] constexpr decltype(auto) errorOr(U&& val) && {
			return this->error_or(std::forward<U>(val));
		}

		template <class U>
		[[nodiscard]] constexpr decltype(auto) errorOr(U&& val) const& {
			return this->error_or(std::forward<U>(val));
		}
	};

	template <class T = impl::DefaultValue>
	constexpr impl::Success<T> Ok() {
		return impl::Success<T>();
	}

	template <class T>
	constexpr impl::Success<T> Ok(T&& value) {
		return impl::Success<T>(std::forward<T>(value));
	}

	template <class E>
	constexpr impl::Failure<E> Err(E&& error) {
		return impl::Failure<E>(std::forward<E>(error));
	}
}

#define TULIP_HOOK_CONCAT2(A_, B_) A_##B_
#define TULIP_HOOK_CONCAT(A_, B_) TULIP_HOOK_CONCAT2(A_, B_)

#define TULIP_HOOK_UNWRAP_INTO(Into_, ...)                                           \
	auto TULIP_HOOK_CONCAT(unwrap_res_, __LINE__) = (__VA_ARGS__);                   \
	if (TULIP_HOOK_CONCAT(unwrap_res_, __LINE__).isErr()) {                          \
		return Err(std::move(TULIP_HOOK_CONCAT(unwrap_res_, __LINE__).unwrapErr())); \
	}                                                                                \
	Into_ = std::move(TULIP_HOOK_CONCAT(unwrap_res_, __LINE__).unwrap())

#define TULIP_HOOK_UNWRAP(...)                                                           \
	{                                                                                    \
		auto TULIP_HOOK_CONCAT(unwrap_res_, __LINE__) = (__VA_ARGS__);                   \
		if (TULIP_HOOK_CONCAT(unwrap_res_, __LINE__).isErr()) {                          \
			return Err(std::move(TULIP_HOOK_CONCAT(unwrap_res_, __LINE__).unwrapErr())); \
		}                                                                                \
	}
