#include "PosixArmV8Target.hpp"

#include <Platform.hpp>
#include <stdexcept>

using namespace tulip::hook;

#if defined(TULIP_HOOK_POSIX) && defined(TULIP_HOOK_ARMV8)

Target& Target::get() {
	static PosixArmV8Target ret;
	return ret;
}

Result<csh> PosixArmV8Target::openCapstone() {
	cs_err status;

	status = cs_open(CS_ARCH_AARCH64, 0, &m_capstone);

	if (status != CS_ERR_OK) {
		return Err("Couldn't open capstone");
	}

	return Ok(m_capstone);
}

std::unique_ptr<HandlerGenerator> PosixArmV8Target::getHandlerGenerator(
	void* address, void* trampoline, void* handler, void* content, void* wrapped, HandlerMetadata const& metadata
) {
	return std::make_unique<ArmV8HandlerGenerator>(address, trampoline, handler, content, wrapped, metadata);
}

std::unique_ptr<WrapperGenerator> PosixArmV8Target::getWrapperGenerator(void* address, WrapperMetadata const& metadata) {
	return std::make_unique<ArmV8WrapperGenerator>(address, metadata);
}

#endif