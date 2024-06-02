#pragma once

#include "X86Generator.hpp"

#include <Platform.hpp>

namespace tulip::hook {

	class X64HandlerGenerator : public X86HandlerGenerator {
	public:
		using X86HandlerGenerator::X86HandlerGenerator;

		std::vector<uint8_t> handlerBytes(uint64_t address) override;
		std::vector<uint8_t> intervenerBytes(uint64_t address) override;
		std::vector<uint8_t> trampolineBytes(uint64_t address, size_t offset) override;

		Result<> relocateRIPInstruction(cs_insn* insn, uint8_t* buffer, uint64_t& trampolineAddress, uint64_t& originalAddress, int64_t disp) override;
	};

	class X64WrapperGenerator : public X86WrapperGenerator {
	public:
		using X86WrapperGenerator::X86WrapperGenerator;

		std::vector<uint8_t> wrapperBytes(uint64_t address) override;
		std::vector<uint8_t> reverseWrapperBytes(uint64_t address) override;
	};
}
