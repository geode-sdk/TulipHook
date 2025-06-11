#pragma once

#include <HandlerData.hpp>
#include <Geode/Result.hpp>
#include <WrapperData.hpp>
#include <memory>

#include <Platform.hpp>
#if defined(TULIP_HOOK_X86) || defined(TULIP_HOOK_X64)
#include <capstone/capstone.h>
#else
typedef size_t csh;
#endif

namespace tulip::hook {
	class HandlerGenerator;
	class WrapperGenerator;

	class Target {
	protected:
		csh m_capstone = 0;

		void* m_allocatedPage = nullptr;
		size_t m_currentOffset = 0;
		size_t m_remainingOffset = 0;

	public:
		static Target& get();

		virtual ~Target() = default;

		geode::Result<void*> allocateArea(size_t size);

		virtual geode::Result<> writeMemory(void* destination, void const* source, size_t size);

		virtual geode::Result<csh> openCapstone() = 0;
		void closeCapstone();
		csh getCapstone();

		virtual geode::Result<> allocatePage() = 0;
		virtual geode::Result<uint32_t> getProtection(void* address) = 0;
		virtual geode::Result<> protectMemory(void* address, size_t size, uint32_t protection) = 0;
		virtual geode::Result<> rawWriteMemory(void* destination, void const* source, size_t size) = 0;
		virtual uint32_t getWritableProtection() = 0;

		virtual std::unique_ptr<HandlerGenerator> getHandlerGenerator(
			void* address, void* trampoline, void* handler, void* content, HandlerMetadata const& metadata
		) = 0;
		virtual std::unique_ptr<WrapperGenerator> getWrapperGenerator(void* address, WrapperMetadata const& metadata) = 0;
		// sorry :( virtual BaseAssembler* getAssembler(int64_t baseAddress);

		// These just exist because of arm7! fun!
		virtual void* getRealPtr(void* ptr);
		virtual void* getRealPtrAs(void* ptr, void* lookup);
	};
};
