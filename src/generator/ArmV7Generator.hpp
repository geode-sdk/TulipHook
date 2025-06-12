#pragma once

#include "Generator.hpp"

#include <Platform.hpp>

namespace tulip::hook {

	class ArmV7HandlerGenerator : public HandlerGenerator {
	public:
		using HandlerGenerator::HandlerGenerator;

		HandlerReturn handlerBytes(uint64_t address) override;
		std::vector<uint8_t> intervenerBytes(uint64_t address, size_t size) override;
		geode::Result<RelocateReturn> relocatedBytes(uint64_t base, uint64_t target, void const* originalBuffer) override;
		geode::Result<TrampolineReturn> trampolineBytes(uint64_t target, void const* originalBuffer) override;
	};

	class ArmV7WrapperGenerator : public WrapperGenerator {
	public:
		using WrapperGenerator::WrapperGenerator;
	};
}
