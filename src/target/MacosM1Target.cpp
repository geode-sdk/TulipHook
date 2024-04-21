#include "MacosM1Target.hpp"

#include <Platform.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_MACOS) && defined(TULIP_HOOK_ARMV8)

Target& Target::get() {
	static MacosM1Target ret;
	return ret;
}

Result<csh> MacosM1Target::openCapstone() {
	// cs_err status;

	// status = cs_open(CS_ARCH_X86, CS_MODE_64, &m_capstone);
	// if (status != CS_ERR_OK) {
		return Err("Couldn't open capstone");
	// }

	// return Ok(m_capstone);
}

std::unique_ptr<HandlerGenerator> MacosM1Target::getHandlerGenerator(
	void* address, void* trampoline, void* handler, void* content, void* wrapped, HandlerMetadata const& metadata
) {
	return std::make_unique<ArmV8HandlerGenerator>(address, trampoline, handler, content, wrapped, metadata);
}

std::unique_ptr<WrapperGenerator> MacosM1Target::getWrapperGenerator(void* address, WrapperMetadata const& metadata) {
	return std::make_unique<ArmV8HandlerGenerator>(address, metadata);
}

#endif