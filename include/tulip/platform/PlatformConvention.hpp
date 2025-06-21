#include "../Platform.hpp"
#include "AAPCS64Convention.hpp"
#include "AAPCSConvention.hpp"
#include "DefaultConvention.hpp"
#include "Windows32Convention.hpp"
#include "Windows64Convention.hpp"
#include "SystemVConvention.hpp"

namespace tulip::hook {
#if defined(TULIP_HOOK_CDECL_CONV)
    using PlatformConvention = CdeclConvention;
#elif defined(TULIP_HOOK_SYSTEMV_CONV)
    using PlatformConvention = SystemVConvention;
#elif defined(TULIP_HOOK_MICROSOFT_X64_CONV)
    using PlatformConvention = Windows64Convention;
#elif defined(TULIP_HOOK_AAPCS_CONV)
    using PlatformConvention = AAPCSConvention;
#elif defined(TULIP_HOOK_AAPCS64_CONV)
    using PlatformConvention = AAPCS64Convention;
#else
    using PlatformConvention = DefaultConvention;
#endif
}