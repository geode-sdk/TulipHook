#pragma once

#include <Platform.hpp>

#if defined(TULIP_HOOK_MACOS) && defined(TULIP_HOOK_X64)

#include "../generator/X64Generator.hpp"
#include "DarwinTarget.hpp"

namespace tulip::hook {
	class MacosIntelTarget : public DarwinTarget {
	public:
		using DarwinTarget::DarwinTarget;

		Result<csh> openCapstone() override;

		std::unique_ptr<HandlerGenerator> getHandlerGenerator(
			void* address, void* trampoline, void* handler, void* content, HandlerMetadata const& metadata
		) override;
		std::unique_ptr<WrapperGenerator> getWrapperGenerator(void* address, WrapperMetadata const& metadata) override;
	};
}

#endif
