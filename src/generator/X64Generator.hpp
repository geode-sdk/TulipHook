#pragma once

#include "X86Generator.hpp"

#include <Platform.hpp>
#include <string_view>
#include <vector>

namespace tulip::hook {
	class X64Assembler;

	class X64Generator : public X86Generator {
	public:
		using X86Generator::X86Generator;

		std::vector<uint8_t> handlerBytes(int64_t original, int64_t handler, void* content, HandlerMetadata const& metadata) override;
		std::vector<uint8_t> intervenerBytes(int64_t original, int64_t handler, size_t size) override;
		std::vector<uint8_t> wrapperBytes(int64_t original, int64_t wrapper, WrapperMetadata const& metadata) override;
		std::vector<uint8_t> runtimeInfoBytes(int64_t function, size_t size, int64_t push, int64_t alloc) override;

		geode::Result<> relocateRIPInstruction(cs_insn* insn, uint8_t* buffer, uint64_t& trampolineAddress, uint64_t& originalAddress, int64_t disp) override;
		geode::Result<> relocateBranchInstruction(cs_insn* insn, uint8_t* buffer, uint64_t& trampolineAddress, uint64_t& originalAddress, int64_t targetAddress, int64_t relocated, size_t originalTarget) override;

	private:
		size_t preserveRegisters(X64Assembler& a);
		void restoreRegisters(X64Assembler& a, size_t size);

		size_t preserveReturnRegisters(X64Assembler& a);
		void restoreReturnRegisters(X64Assembler& a, size_t size);
	};
}
