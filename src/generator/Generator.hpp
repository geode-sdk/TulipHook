#pragma once

#include <FunctionData.hpp>
#include <HandlerData.hpp>
#include <TulipResult.hpp>
#include <WrapperData.hpp>
#include <memory>

namespace tulip::hook {

	class HandlerGenerator {
	public:
		void* const m_address;
		void* const m_trampoline;
		void* const m_handler;
		void* const m_content;
		HandlerMetadata const m_metadata;

		HandlerGenerator(
			void* address, void* trampoline, void* handler, void* content, HandlerMetadata const& metadata
		);

		virtual ~HandlerGenerator() = default;

		virtual Result<FunctionData> generateHandler();
		virtual Result<std::vector<uint8_t>> generateIntervener();

		struct RelocateReturn {
			std::vector<uint8_t> m_relocatedBytes;
			int64_t m_originalOffset;
		};

		virtual Result<FunctionData> generateTrampoline(uint64_t target);

		virtual std::vector<uint8_t> handlerBytes(uint64_t address);
		virtual std::vector<uint8_t> intervenerBytes(uint64_t address);
		virtual std::vector<uint8_t> trampolineBytes(uint64_t address, size_t offset);
		virtual Result<RelocateReturn> relocatedBytes(uint64_t base, uint64_t target);
	};

	class WrapperGenerator {
	public:
		void* const m_address;
		WrapperMetadata const m_metadata;

		virtual ~WrapperGenerator() = default;

		WrapperGenerator(void* address, WrapperMetadata const& metadata);

		virtual Result<FunctionData> generateWrapper();
		virtual Result<FunctionData> generateReverseWrapper();

		virtual std::vector<uint8_t> wrapperBytes(uint64_t address);
		virtual std::vector<uint8_t> reverseWrapperBytes(uint64_t address);
	};
}
