#pragma once

#include "Generator.hpp"

#include <Platform.hpp>

namespace tulip::hook {

    class ArmV7Generator : public BaseGenerator {
    public:
        using BaseGenerator::BaseGenerator;

        std::vector<uint8_t> handlerBytes(
            int64_t original, int64_t handler, void* content,
            HandlerMetadata const& metadata
        ) override;
        std::vector<uint8_t> intervenerBytes(int64_t original, int64_t handler, size_t size) override;
        geode::Result<RelocateReturn> relocatedBytes(
            int64_t original, int64_t relocated,
            std::span<uint8_t const> originalBuffer, size_t targetSize
        ) override;
    };
}
