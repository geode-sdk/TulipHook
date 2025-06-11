#pragma once

#include <FunctionData.hpp>
#include <HandlerData.hpp>
#include <Geode/Result.hpp>
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

		virtual geode::Result<FunctionData> generateHandler();
		virtual geode::Result<std::vector<uint8_t>> generateIntervener(int64_t size);

		struct RelocateReturn {
			std::vector<uint8_t> m_relocatedBytes;
			size_t m_originalOffset;
		};

		struct TrampolineReturn {
			std::vector<uint8_t> m_trampolineBytes;
			size_t m_codeSize;
			size_t m_originalOffset;
		};

		struct HandlerReturn {
			std::vector<uint8_t> m_handlerBytes;
			size_t m_codeSize;
		};

		struct GeneratedTrampolineReturn {
			size_t m_codeSize;
			size_t m_originalOffset;
		};

		virtual geode::Result<GeneratedTrampolineReturn> generateTrampoline(uint64_t target, void const* originalBuffer);

		virtual HandlerReturn handlerBytes(uint64_t address);
		virtual std::vector<uint8_t> intervenerBytes(uint64_t address, size_t size);
		virtual geode::Result<TrampolineReturn> trampolineBytes(uint64_t target, void const* originalBuffer);
		virtual geode::Result<RelocateReturn> relocatedBytes(uint64_t base, uint64_t target, void const* originalBuffer);
	};

	class WrapperGenerator {
	public:
		void* const m_address;
		WrapperMetadata const m_metadata;

		virtual ~WrapperGenerator() = default;

		WrapperGenerator(void* address, WrapperMetadata const& metadata);

		virtual geode::Result<FunctionData> generateWrapper();
		virtual geode::Result<FunctionData> generateReverseWrapper();

		virtual std::vector<uint8_t> wrapperBytes(uint64_t address);
		virtual std::vector<uint8_t> reverseWrapperBytes(uint64_t address);
	};
}
