#pragma once

#include <Platform.hpp>

#if defined(TULIP_HOOK_WINDOWS)

#include "../generator/X86Generator.hpp"
#include "Target.hpp"

namespace tulip::hook {
    class Windows32Target : public Target {
    public:
        using Target::Target;

        geode::Result<csh> openCapstone() override;

        geode::Result<> allocatePage() override;
        geode::Result<uint32_t> getProtection(void* address) override;
        geode::Result<> protectMemory(void* address, size_t size, uint32_t protection) override;
        geode::Result<> rawWriteMemory(void* destination, void const* source, size_t size) override;
        uint32_t getWritableProtection() override;

        std::unique_ptr<BaseGenerator> getGenerator() override;

        std::shared_ptr<CallingConvention> createConvention(TulipConvention convention) noexcept override;
    };
}

#endif
