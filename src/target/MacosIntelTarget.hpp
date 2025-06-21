#pragma once

#include <Platform.hpp>

#if defined(TULIP_HOOK_MACOS) && defined(TULIP_HOOK_X64)

#include "../generator/X64Generator.hpp"
#include "DarwinTarget.hpp"

namespace tulip::hook {
	class MacosIntelTarget : public DarwinTarget {
	public:
		using DarwinTarget::DarwinTarget;

		geode::Result<csh> openCapstone() override;

		std::unique_ptr<BaseGenerator> getGenerator() override;

		std::shared_ptr<CallingConvention> createConvention(TulipConvention convention) noexcept override;
	};
}

#endif
