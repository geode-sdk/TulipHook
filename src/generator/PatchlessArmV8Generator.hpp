#pragma once

#include "ArmV8Generator.hpp"

#include <Platform.hpp>

namespace tulip::hook {

	class PatchlessArmV8HandlerGenerator : public ArmV8HandlerGenerator {
	public:
		using ArmV8HandlerGenerator::ArmV8HandlerGenerator;

		HandlerReturn handlerBytes(uint64_t address) override;
		std::vector<uint8_t> intervenerBytes(uint64_t address, size_t size) override;
	};
}
