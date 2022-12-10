#pragma once

#include "../Target.hpp"

#include <Platform.hpp>

#if defined(TULIP_HOOK_WINDOWS)

namespace tulip::hook {

	class WindowsTarget : public Target {
	public:
		using Target::Target;

		static WindowsTarget& get();

		Result<ks_engine*> openKeystone() override;
		Result<csh> openCapstone() override;

		Result<> allocatePage() override;
		Result<uint32_t> getProtection(void* address) override;
		Result<> protectMemory(void* address, size_t size, uint32_t protection) override;
		Result<> rawWriteMemory(void* destination, void* source, size_t size) override;
		uint32_t getMaxProtection() override;
	};

	using PlatformTarget = WindowsTarget;

}

#endif