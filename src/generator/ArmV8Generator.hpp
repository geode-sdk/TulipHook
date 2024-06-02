#pragma once

#include "Generator.hpp"

#include <Platform.hpp>

namespace tulip::hook {

	class ArmV8HandlerGenerator : public HandlerGenerator {
	public:
		using HandlerGenerator::HandlerGenerator;

		Result<> generateTrampoline(uint64_t target) override;

		std::vector<uint8_t> handlerBytes(uint64_t address) override;
		std::vector<uint8_t> intervenerBytes(uint64_t address) override;
	};

	class ArmV8WrapperGenerator : public WrapperGenerator {
	public:
		using WrapperGenerator::WrapperGenerator;
	};
}
