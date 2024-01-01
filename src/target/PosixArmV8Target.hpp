#pragma once

#include "../generator/ArmV8Generator.hpp"
#include "PosixTarget.hpp"

#include <Platform.hpp>

#if defined(TULIP_HOOK_POSIX) && defined(TULIP_HOOK_ARMV8)

namespace tulip::hook {
	class PosixArmV8Target : public PosixTarget {
	public:
		using PosixTarget::PosixTarget;

		Result<csh> openCapstone() override;

		std::unique_ptr<HandlerGenerator> getHandlerGenerator(
			void* address, void* trampoline, void* handler, void* content, void* wrapped, HandlerMetadata const& metadata
		) override;
		std::unique_ptr<WrapperGenerator> getWrapperGenerator(void* address, WrapperMetadata const& metadata) override;
	};
}

#endif