#include "PosixArmV7Target.hpp"

#include <Platform.hpp>
#include <stdexcept>

using namespace tulip::hook;

#if defined(TULIP_HOOK_POSIX) && defined(TULIP_HOOK_ARMV7)

#include <sys/mman.h>

Target& Target::get() {
	static PosixArmV7Target ret;
	return ret;
}

geode::Result<csh> PosixArmV7Target::openCapstone() {
	//cs_err status;

	//status = cs_open(CS_ARCH_ARM, CS_MODE_32, &m_capstone);

	//if (status != CS_ERR_OK) {
		return geode::Err("Couldn't open capstone");
	//}

	//return geode::Ok(m_capstone);
}

std::unique_ptr<BaseGenerator> PosixArmV7Target::getGenerator() {
	return std::make_unique<ArmV7Generator>();
}

// Thumb is very fun to deal with!
int64_t PosixArmV7Target::getRealPtr(void* ptr) {
	return reinterpret_cast<int64_t>(ptr) & (~1ll);
}
int64_t PosixArmV7Target::getRealPtrAs(void* ptr, void* lookup) {
	return this->getRealPtr(ptr) | (reinterpret_cast<int64_t>(lookup) & 1ll);
}

std::shared_ptr<CallingConvention> PosixArmV7Target::createConvention(TulipConvention convention) noexcept {
	return AAPCSConvention::create();
}

#endif
