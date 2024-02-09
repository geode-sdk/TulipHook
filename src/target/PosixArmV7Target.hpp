#pragma once

#include <Platform.hpp>

#if defined(TULIP_HOOK_POSIX) && defined(TULIP_HOOK_ARMV7)

#include "../generator/ArmV7Generator.hpp"
#include "PosixTarget.hpp"

namespace tulip::hook {
	class PosixArmV7Target : public PosixTarget {
	public:
		using PosixTarget::PosixTarget;

		Result<csh> openCapstone() override;

		std::unique_ptr<HandlerGenerator> getHandlerGenerator(
			void* address, void* trampoline, void* handler, void* content, void* wrapped, HandlerMetadata const& metadata
		) override;
		std::unique_ptr<WrapperGenerator> getWrapperGenerator(void* address, WrapperMetadata const& metadata) override;

		void* getRealPtr(void* ptr) override;
		void* getRealPtrAs(void* ptr, void* lookup) override;
	};
}

#endif
