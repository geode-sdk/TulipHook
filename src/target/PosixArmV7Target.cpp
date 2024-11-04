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

std::unique_ptr<HandlerGenerator> PosixArmV7Target::getHandlerGenerator(
	void* address, void* trampoline, void* handler, void* content, HandlerMetadata const& metadata
) {
	return std::make_unique<ArmV7HandlerGenerator>(address, trampoline, handler, content, metadata);
}

std::unique_ptr<WrapperGenerator> PosixArmV7Target::getWrapperGenerator(void* address, WrapperMetadata const& metadata) {
	return std::make_unique<ArmV7WrapperGenerator>(address, metadata);
}

// Thumb is very fun to deal with!
void* PosixArmV7Target::getRealPtr(void* ptr) {
	return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(ptr) & (~1));
}
void* PosixArmV7Target::getRealPtrAs(void* ptr, void* lookup) {
	return reinterpret_cast<void*>(
		reinterpret_cast<uintptr_t>(this->getRealPtr(ptr)) |
		(reinterpret_cast<uintptr_t>(lookup) & 1)
	);
}

#endif
