#include <Error.hpp>

using namespace tulip::hook;
std::string tulip::hook::Error::toString() const {
    switch (m_value) {
        case Unknown:
            return "Unknown error";
        case RuntimeInterveneDisabled:
            return "Runtime intervening is disabled";
        case NotImplemented:
            if (m_message.size()) return "Method not implemented: " + m_message;
            return "Method not implemented";
        case HandlerNotFound:
            return "Handler not found";
        case CommonHandlerNotGiven:
            return "Could not find a common handler to disable runtime intervening";
        case FailedToRelocate:
            if (m_message.size()) return "Failed to relocate the code block: " + m_message;
            return "Failed to relocate the code block";
        case AllocatePageFail:
            if (m_message.size()) return "Failed to allocate page: " + m_message;
            return "Failed to allocate page";
        case GetProtectionFail:
            if (m_message.size()) return "Failed to get protection: " + m_message;
            return "Failed to get protection";
        case ProtectMemoryFail:
            if (m_message.size()) return "Failed to protect memory: " + m_message;
            return "Failed to protect memory";
        case WriteMemoryFail:
            if (m_message.size()) return "Failed to write to memory: " + m_message;
            return "Failed to write to memory";
        case CapstoneError:
            if (m_message.size()) return "Capstone error: " + m_message;
            return "Capstone error"
    }
}
