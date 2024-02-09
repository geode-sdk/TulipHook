#pragma once

#include <Platform.hpp>

#if defined(TULIP_HOOK_POSIX)

#include "Target.hpp"

namespace tulip::hook {

	class PosixTarget : public Target {
	public:
		using Target::Target;

		Result<> allocatePage() override;
		Result<uint32_t> getProtection(void* address) override;
		Result<> protectMemory(void* address, size_t size, uint32_t protection) override;
		Result<> rawWriteMemory(void* destination, void const* source, size_t size) override;
		uint32_t getMaxProtection() override;
	};

}

#endif
