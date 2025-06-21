#pragma once

#include <Geode/Result.hpp>

namespace tulip::hook {

    class Misc {
    public:
        static geode::Result<void*> followJumps(void* address);
    };
}