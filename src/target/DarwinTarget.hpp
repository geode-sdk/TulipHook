#pragma once

#include <Platform.hpp>

#if defined(TULIP_HOOK_DARWIN)

#include "Target.hpp"

namespace tulip::hook {
	class DarwinTarget : public Target {
	public:
		using Target::Target;

		geode::Result<> allocatePage() override;
		geode::Result<uint32_t> getProtection(void* address) override;
		geode::Result<> protectMemory(void* address, size_t size, uint32_t protection) override;
		geode::Result<> rawWriteMemory(void* destination, void const* source, size_t size) override;
		uint32_t getWritableProtection() override;

	protected:
		void internalProtectMemory(void* address, size_t size, uint32_t protection, int& errorCode);
		void internalWriteMemory(void* destination, void const* source, size_t size, int& errorCode);
	};
}

#endif
