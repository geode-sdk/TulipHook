#pragma once

#include <string>
#include <ostream>
#include "Platform.hpp"
#include <Geode/Result.hpp>

namespace tulip::hook {
	struct Error {
        enum {
            Unknown = -1,
            RuntimeInterveneDisabled = 0,
            NotImplemented,
            HandlerNotFound,
            CommonHandlerNotGiven,
            FailedToRelocate,
            AllocatePageFail,
            GetProtectionFail,
            ProtectMemoryFail,
            WriteMemoryFail,
            CapstoneError,
        };

        decltype(Unknown) m_value = Unknown;
        std::string m_message;

        constexpr ~Error() = default;
        constexpr Error() = default;
        constexpr Error(decltype(Unknown) value) : m_value(value) {}
        Error(decltype(Unknown) value, std::string message) : m_value(value), m_message(message) {}
        constexpr Error& operator=(decltype(Unknown) value) {
            m_value = value;
            return *this;
        }
        constexpr decltype(Unknown) value() const{
            return m_value;
        }

        TULIP_HOOK_DLL std::string toString() const;
        operator std::string() const {
            return this->toString();
        }
    };

    template <class OkType = void>
    using Result = geode::Result<OkType, Error>;

    using geode::Ok;
    using geode::Err;

	inline std::string format_as(Error const& err) {
	    return err.toString();
	}
	
	inline std::ostream& operator<<(std::ostream& os, Error const& err) {
	    return os << err.toString();
	}
}
