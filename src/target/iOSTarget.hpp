#pragma once

#include <Platform.hpp>

#if defined(TULIP_HOOK_IOS) && defined(TULIP_HOOK_ARMV8)

#include "../generator/ArmV8Generator.hpp"
#include "DarwinTarget.hpp"

namespace tulip::hook {
	class iOSTarget : public DarwinTarget {
	public:
		using DarwinTarget::DarwinTarget;

		geode::Result<csh> openCapstone() override;

		std::unique_ptr<HandlerGenerator> getHandlerGenerator(
			void* address, void* trampoline, void* handler, void* content, HandlerMetadata const& metadata
		) override;
		std::unique_ptr<WrapperGenerator> getWrapperGenerator(void* address, WrapperMetadata const& metadata) override;

        uint32_t getWritableProtection() override;
	};
}

#endif
