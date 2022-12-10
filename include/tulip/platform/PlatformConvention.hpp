#include "../Platform.hpp"
#include "DefaultConvention.hpp"
#include "WindowsConvention.hpp"

namespace tulip::hook {
#if defined(TULIP_HOOK_WINDOWS)
	using PlatformConvention = CdeclConvention;
#else
	using PlatformConvention = DefaultConvention;
#endif
}