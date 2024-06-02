#include "../Platform.hpp"
#include "DefaultConvention.hpp"
#include "Windows32Convention.hpp"
#include "Windows64Convention.hpp"
#include "MacosIntelConvention.hpp"

namespace tulip::hook {
#if defined(TULIP_HOOK_WINDOWS) && defined(TULIP_HOOK_X86)
	using PlatformConvention = CdeclConvention;
#elif defined(TULIP_HOOK_MACOS) && defined(TULIP_HOOK_X64)
	using PlatformConvention = SystemVConvention;
#else
	using PlatformConvention = DefaultConvention;
#endif
}