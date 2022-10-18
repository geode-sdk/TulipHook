#pragma once

#include <HandlerData.hpp>

#include <memory>

namespace tulip::hook {

	class Generator {
	public:
		void* const m_address;
		void* const m_trampoline;
		void* const m_handler;
		HandlerMetadata const m_metadata;

		Generator(void* address, void* trampoline, void* handler, HandlerMetadata metadata);

		virtual void generateHandler() = 0;
		virtual std::vector<uint8_t> generateIntervener() = 0;
		virtual void generateTrampoline(size_t offset) = 0;
		virtual size_t relocateOriginal(size_t target) = 0;

		virtual std::string handlerString() = 0;
		virtual std::string intervenerString() = 0;
		virtual std::string trampolineString(size_t offset) = 0;
	};
}