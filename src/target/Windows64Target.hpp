#pragma once

#include <Platform.hpp>

#if defined(TULIP_HOOK_WINDOWS) && defined(TULIP_HOOK_X64)

#include "../generator/X64Generator.hpp"
#include "Windows32Target.hpp"

namespace tulip::hook {
	class Windows64Target : public Windows32Target {
	public:
		using Windows32Target::Windows32Target;

		Result<csh> openCapstone() override;

		std::unique_ptr<HandlerGenerator> getHandlerGenerator(
			void* address, void* trampoline, void* handler, void* content, HandlerMetadata const& metadata
		) override;
		std::unique_ptr<WrapperGenerator> getWrapperGenerator(void* address, WrapperMetadata const& metadata) override;
	};
}

#endif
