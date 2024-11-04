#pragma once

#include "Generator.hpp"

#include <Platform.hpp>
#include <capstone/capstone.h>
#include <unordered_map>

namespace tulip::hook {

	class X86HandlerGenerator : public HandlerGenerator {
	protected:
		uint64_t m_modifiedBytesSize = 0;
		// this is only relevant for 64-bit relocation, pointer is to the buffer so dont keep this around
		std::unordered_map<int64_t, int8_t*> m_shortBranchRelocations;
	public:
		using HandlerGenerator::HandlerGenerator;

		geode::Result<RelocateReturn> relocatedBytes(uint64_t base, uint64_t target) override;

		std::vector<uint8_t> handlerBytes(uint64_t address) override;
		std::vector<uint8_t> intervenerBytes(uint64_t address) override;

		geode::Result<FunctionData> generateTrampoline(uint64_t target) override;

		virtual geode::Result<> relocateInstruction(cs_insn* insn, uint8_t* buffer, uint64_t& trampolineAddress, uint64_t& originalAddress);
		virtual geode::Result<> relocateRIPInstruction(cs_insn* insn, uint8_t* buffer, uint64_t& trampolineAddress, uint64_t& originalAddress, int64_t disp);
		virtual geode::Result<> relocateBranchInstruction(cs_insn* insn, uint8_t* buffer, uint64_t& trampolineAddress, uint64_t& originalAddress, int64_t targetAddress);
	};

	class X86WrapperGenerator : public WrapperGenerator {
	public:
		using WrapperGenerator::WrapperGenerator;

		geode::Result<FunctionData> generateWrapper() override;
		// geode::Result<void*> generateReverseWrapper() override;

		std::vector<uint8_t> wrapperBytes(uint64_t address) override;
		// std::vector<uint8_t> reverseWrapperBytes(uint64_t address) override;
	};

}
