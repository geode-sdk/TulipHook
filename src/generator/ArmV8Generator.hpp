#pragma once

#include "Armv7Generator.hpp"

#include <Platform.hpp>

namespace tulip::hook {

	class ArmV8HandlerGenerator : public ArmV7HandlerGenerator {
	public:
		using ArmV7HandlerGenerator::ArmV7HandlerGenerator;

		HandlerReturn handlerBytes(uint64_t address) override;
		std::vector<uint8_t> intervenerBytes(uint64_t address, size_t size) override;
	};

	class ArmV8WrapperGenerator : public ArmV7WrapperGenerator {
	public:
		using ArmV7WrapperGenerator::ArmV7WrapperGenerator;
	};
}
