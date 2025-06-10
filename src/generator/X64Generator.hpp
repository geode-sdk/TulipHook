#pragma once

#include "X86Generator.hpp"

#include <Platform.hpp>
#include <string_view>
#include <vector>

namespace tulip::hook {
	class X64Assembler;

	class X64HandlerGenerator : public X86HandlerGenerator {
	public:
		using X86HandlerGenerator::X86HandlerGenerator;

		// std::vector<uint8_t> handlerBytes(uint64_t address) override;
		std::vector<uint8_t> intervenerBytes(uint64_t address, size_t size) override;

		HandlerReturn handlerBytes(uint64_t address) override;

		geode::Result<TrampolineReturn> trampolineBytes(uint64_t target, void const* originalBuffer) override;

		geode::Result<> relocateRIPInstruction(cs_insn* insn, uint8_t* buffer, uint64_t& trampolineAddress, uint64_t& originalAddress, int64_t disp) override;
		geode::Result<> relocateBranchInstruction(cs_insn* insn, uint8_t* buffer, uint64_t& trampolineAddress, uint64_t& originalAddress, int64_t targetAddress) override;

	private:
		size_t preserveRegisters(X64Assembler& a);
		void restoreRegisters(X64Assembler& a, size_t size);

		size_t preserveReturnRegisters(X64Assembler& a);
		void restoreReturnRegisters(X64Assembler& a, size_t size);
	};

	class X64WrapperGenerator : public X86WrapperGenerator {
	public:
		using X86WrapperGenerator::X86WrapperGenerator;

		std::vector<uint8_t> wrapperBytes(uint64_t address) override;

#ifdef TULIP_HOOK_WINDOWS
		std::vector<uint8_t> unwindInfoBytes(uint64_t address);
#endif

		geode::Result<FunctionData> generateWrapper() override;
		// std::vector<uint8_t> reverseWrapperBytes(uint64_t address) override;
	};
}
