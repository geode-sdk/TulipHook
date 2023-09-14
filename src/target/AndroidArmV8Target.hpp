#pragma once

#include "AndroidTarget.hpp"
#include "Target.hpp"

#include <Platform.hpp>

#if defined(TULIP_HOOK_ANDROID) && defined(TULIP_HOOK_ARMV7)

namespace tulip::hook {
	class AndroidArmV8Target : public AndroidTarget {
	public:
		using Target::Target;

		static AndroidArmV8Target& get();

		Result<csh> openCapstone() override;

		std::unique_ptr<HandlerGenerator> getHandlerGenerator(
			void* address, void* trampoline, void* handler, void* content, void* wrapped, HandlerMetadata const& metadata
		) override;
		std::unique_ptr<WrapperGenerator> getWrapperGenerator(void* address, WrapperMetadata const& metadata) override;
	};

	using PlatformTarget = AndroidArmV8Target;
}

#endif