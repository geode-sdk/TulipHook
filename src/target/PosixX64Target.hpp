#pragma once

#include <Platform.hpp>

#if defined(TULIP_HOOK_POSIX) && defined(TULIP_HOOK_X64)

#include "PosixTarget.hpp"

namespace tulip::hook {
	class PosixX64Target : public PosixTarget {
	public:
		using PosixTarget::PosixTarget;

		geode::Result<csh> openCapstone() override;

		std::unique_ptr<BaseGenerator> getGenerator() override;

		std::shared_ptr<CallingConvention> createConvention(TulipConvention convention) noexcept override;
	};
}

#endif
