#pragma once

#include <HookData.hpp>
#include <map>

namespace tulip::hook {

    class Hook {
    public:
        HookMetadata m_metadata;

        void* m_address;

        Hook(void* address, HookMetadata metadata) : m_address(address), m_metadata(metadata) {}

        ~Hook() {}
    };
}