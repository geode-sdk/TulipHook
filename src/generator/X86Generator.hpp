#pragma once

#include "Generator.hpp"

#include <Platform.hpp>
#include <capstone/capstone.h>
#include <unordered_map>

namespace tulip::hook {

	class X86Generator : public BaseGenerator {
	protected:
		// this is only relevant for 64-bit relocation, pointer is to the buffer so dont keep this around
		std::unordered_map<int64_t, int8_t*> m_shortBranchRelocations;
	public:
		using BaseGenerator::BaseGenerator;

		std::vector<uint8_t> handlerBytes(int64_t original, int64_t handler, void* content, HandlerMetadata const& metadata) override;
		std::vector<uint8_t> intervenerBytes(int64_t original, int64_t handler, size_t size) override;
		geode::Result<RelocateReturn> relocatedBytes(int64_t original, int64_t relocated, size_t size) override;
		std::vector<uint8_t> wrapperBytes(int64_t original, int64_t wrapper, WrapperMetadata const& metadata) override;

		virtual geode::Result<> relocateInstruction(cs_insn* insn, uint8_t* buffer, uint64_t& trampolineAddress, uint64_t& originalAddress, int64_t relocated, size_t originalTarget);
		virtual geode::Result<> relocateRIPInstruction(cs_insn* insn, uint8_t* buffer, uint64_t& trampolineAddress, uint64_t& originalAddress, int64_t disp);
		virtual geode::Result<> relocateBranchInstruction(cs_insn* insn, uint8_t* buffer, uint64_t& trampolineAddress, uint64_t& originalAddress, int64_t targetAddress, int64_t relocated, size_t originalTarget);
	};

}
