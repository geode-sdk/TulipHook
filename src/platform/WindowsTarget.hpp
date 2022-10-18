#pragma once

#include <Platform.hpp>
#include "../Target.hpp"

#if defined(TULIP_HOOK_WINDOWS)

namespace tulip::hook {

	class WindowsTarget : public Target {
	public:
		using Target::Target;

		static WindowsTarget& get();

		ks_engine* openKeystone() override;
		csh openCapstone() override;

		void allocatePage() override;
		uint32_t getProtection(void* address) override;
		void protectMemory(void* address, size_t size, uint32_t protection) override;
		void rawWriteMemory(void* destination, void* source, size_t size) override;
		uint32_t getMaxProtection() override;
	};

	using PlatformTarget = WindowsTarget;

}

#endif