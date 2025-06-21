#pragma once

#include <Platform.hpp>

#if defined(TULIP_HOOK_WINDOWS) && defined(TULIP_HOOK_X64)

#include "../generator/X64Generator.hpp"
#include "Windows32Target.hpp"

namespace tulip::hook {
	class Windows64Target : public Windows32Target {
	public:
		using Windows32Target::Windows32Target;

		geode::Result<csh> openCapstone() override;

		geode::Result<> allocatePage() override;
		std::unique_ptr<BaseGenerator> getGenerator() override;

		std::shared_ptr<CallingConvention> createConvention(TulipConvention convention) noexcept override;
	};
}

#endif
