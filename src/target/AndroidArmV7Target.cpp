#include "AndroidArmV7Target.hpp"

#include <Platform.hpp>
#include <stdexcept>

using namespace tulip::hook;

#if defined(TULIP_HOOK_ANDROID) && defined(TULIP_HOOK_ARMV7)

#include <sys/mman.h>

Target& Target::get() {
	static AndroidArmV7Target ret;
	return ret;
}

Result<csh> AndroidArmV7Target::openCapstone() {
	cs_err status;

	status = cs_open(CS_ARCH_ARM, CS_MODE_32, &m_capstone);

	if (status != CS_ERR_OK) {
		return Err("Couldn't open capstone");
	}

	return Ok(m_capstone);
}

std::unique_ptr<HandlerGenerator> AndroidArmV7Target::getHandlerGenerator(
	void* address, void* trampoline, void* handler, void* content, void* wrapped, HandlerMetadata const& metadata
) {
	return std::make_unique<ArmV7HandlerGenerator>(address, trampoline, handler, content, wrapped, metadata);
}

std::unique_ptr<WrapperGenerator> AndroidArmV7Target::getWrapperGenerator(void* address, WrapperMetadata const& metadata) {
	return std::make_unique<ArmV7WrapperGenerator>(address, metadata);
}

#endif