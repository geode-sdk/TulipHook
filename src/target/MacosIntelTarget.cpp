#include "MacosIntelTarget.hpp"

#include <Platform.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_MACOS) && defined(TULIP_HOOK_X64)

Target& Target::get() {
    static MacosIntelTarget ret;
    return ret;
}

geode::Result<csh> MacosIntelTarget::openCapstone() {
    cs_err status;

    status = cs_open(CS_ARCH_X86, CS_MODE_64, &m_capstone);
    if (status != CS_ERR_OK) {
        return geode::Err("Couldn't open capstone");
    }

    return geode::Ok(m_capstone);
}

std::unique_ptr<BaseGenerator> MacosIntelTarget::getGenerator() {
    return std::make_unique<X64Generator>();
}

std::shared_ptr<CallingConvention> MacosIntelTarget::createConvention(TulipConvention convention) noexcept {
    return SystemVConvention::create();
}

#endif