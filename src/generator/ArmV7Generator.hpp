#pragma once

#include "Generator.hpp"

#include <Platform.hpp>

namespace tulip::hook {

	class ArmV7HandlerGenerator : public HandlerGenerator {
	public:
		using HandlerGenerator::HandlerGenerator;

		Result<> generateTrampoline(RelocateReturn offsets) override;
		Result<RelocateReturn> relocateOriginal(uint64_t target) override;

		std::vector<uint8_t> handlerBytes(uint64_t address) override;
		std::vector<uint8_t> intervenerBytes(uint64_t address) override;
		std::vector<uint8_t> trampolineBytes(uint64_t address, size_t offset) override;

		void relocateInstruction(cs_insn* insn, uint64_t& trampolineAddress, uint64_t& originalAddress) override;
	};

	class ArmV7WrapperGenerator : public WrapperGenerator {
	public:
		using WrapperGenerator::WrapperGenerator;
	};
}
