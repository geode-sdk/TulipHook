#include "PosixArmV8Target.hpp"

#include <Platform.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_POSIX) && defined(TULIP_HOOK_ARMV8)

#include "../generator/ArmV8Generator.hpp"

Target& Target::get() {
	static PosixArmV8Target ret;
	return ret;
}

geode::Result<csh> PosixArmV8Target::openCapstone() {
	//cs_err status;

	//status = cs_open(CS_ARCH_ARM64, static_cast<cs_mode>(0), &m_capstone);

	//if (status != CS_ERR_OK) {
		return geode::Err("Couldn't open capstone");
	//}

	//return geode::Ok(m_capstone);
}

std::unique_ptr<BaseGenerator> PosixArmV8Target::getGenerator() {
	return std::make_unique<ArmV8Generator>();
}

std::shared_ptr<CallingConvention> PosixArmV8Target::createConvention(TulipConvention convention) noexcept {
	return AAPCS64Convention::create();
}

#endif
