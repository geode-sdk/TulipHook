#pragma once

#include <Platform.hpp>

#if defined(TULIP_HOOK_POSIX) && defined(TULIP_HOOK_ARMV7)

#include "../generator/ArmV7Generator.hpp"
#include "PosixTarget.hpp"

namespace tulip::hook {
    class PosixArmV7Target : public PosixTarget {
    public:
        using PosixTarget::PosixTarget;

        geode::Result<csh> openCapstone() override;

        std::unique_ptr<BaseGenerator> getGenerator() override;

        int64_t getRealPtr(void* ptr) override;
        int64_t getRealPtrAs(void* ptr, void* lookup) override;

        std::shared_ptr<CallingConvention> createConvention(TulipConvention convention) noexcept override;
    };
}

#endif
