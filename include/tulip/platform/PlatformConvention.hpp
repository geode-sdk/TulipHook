#include "../Platform.hpp"
#include "DefaultConvention.hpp"
#include "Windows32Convention.hpp"
#include "Windows64Convention.hpp"

namespace tulip::hook {
#if defined(TULIP_HOOK_WINDOWS) && defined(TULIP_HOOK_X86)
	using PlatformConvention = CdeclConvention;
#else
	using PlatformConvention = DefaultConvention;
#endif
}