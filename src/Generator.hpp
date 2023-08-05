#pragma once

#include <HandlerData.hpp>
#include <TulipResult.hpp>
#include <WrapperData.hpp>
#include <capstone/capstone.h>
#include <memory>

namespace tulip::hook {

	class HandlerGenerator {
	public:
		void* const m_address;
		void* const m_trampoline;
		void* const m_handler;
		void* const m_content;
		void* const m_wrapped;
		HandlerMetadata const m_metadata;

		HandlerGenerator(
			void* address, void* trampoline, void* handler, void* content, void* wrapped, HandlerMetadata const& metadata
		);

		virtual Result<> generateHandler() = 0;
		virtual Result<std::vector<uint8_t>> generateIntervener() = 0;

		struct RelocateReturn {
			uint64_t m_trampolineOffset;
			uint64_t m_originalOffset;
		};

		virtual Result<> generateTrampoline(RelocateReturn offsets) = 0;
		virtual Result<RelocateReturn> relocateOriginal(uint64_t target) = 0;

		virtual std::string handlerString() = 0;
		virtual std::string intervenerString() = 0;
		virtual std::string trampolineString(size_t offset) = 0;

		virtual std::vector<uint8_t> handlerBytes(uint64_t address) = 0;
		virtual std::vector<uint8_t> intervenerBytes(uint64_t address) = 0;
		virtual std::vector<uint8_t> trampolineBytes(uint64_t address, size_t offset) = 0;

		virtual void relocateInstruction(cs_insn* insn, uint64_t& trampolineAddress, uint64_t& originalAddress) = 0;
	};

	class WrapperGenerator {
	public:
		void* const m_address;
		WrapperMetadata const m_metadata;

		WrapperGenerator(void* address, WrapperMetadata const& metadata);

		virtual Result<void*> generateWrapper() = 0;
		virtual Result<void*> generateReverseWrapper() = 0;

		virtual std::string wrapperString() = 0;
		virtual std::string reverseWrapperString() = 0;

		virtual std::vector<uint8_t> wrapperBytes(uint64_t address) = 0;
		virtual std::vector<uint8_t> reverseWrapperBytes(uint64_t address) = 0;
	};
}