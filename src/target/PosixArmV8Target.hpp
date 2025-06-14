#pragma once

#include <Platform.hpp>

#if defined(TULIP_HOOK_POSIX) && defined(TULIP_HOOK_ARMV8)

#include "../generator/ArmV8Generator.hpp"
#include "PosixTarget.hpp"

namespace tulip::hook {
	class PosixArmV8Target : public PosixTarget {
	public:
		using PosixTarget::PosixTarget;

		geode::Result<csh> openCapstone() override;

		std::unique_ptr<BaseGenerator> getGenerator() override;
	};
}

#endif
