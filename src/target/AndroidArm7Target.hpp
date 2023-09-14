#pragma once

#include "../generator/Arm7Generator.hpp"
#include "AndroidTarget.hpp"

#include <Platform.hpp>

#if defined(TULIP_HOOK_ANDROID) && defined(TULIP_HOOK_ARM_7)

namespace tulip::hook {
	class AndroidArm7Target : public AndroidTarget {
	public:
		using AndroidTarget::AndroidTarget;

		static AndroidArm7Target& get();

		Result<csh> openCapstone() override;

		std::unique_ptr<HandlerGenerator> getHandlerGenerator(
			void* address, void* trampoline, void* handler, void* content, void* wrapped, HandlerMetadata const& metadata
		) override;
		std::unique_ptr<WrapperGenerator> getWrapperGenerator(void* address, WrapperMetadata const& metadata) override;
	};

	using PlatformTarget = AndroidArm7Target;
}

#endif