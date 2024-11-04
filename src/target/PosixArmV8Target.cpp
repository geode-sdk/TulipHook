#include "PosixArmV8Target.hpp"

#include <Platform.hpp>
#include <stdexcept>

using namespace tulip::hook;

#if defined(TULIP_HOOK_POSIX) && defined(TULIP_HOOK_ARMV8)

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

std::unique_ptr<HandlerGenerator> PosixArmV8Target::getHandlerGenerator(
	void* address, void* trampoline, void* handler, void* content, HandlerMetadata const& metadata
) {
	return std::make_unique<ArmV8HandlerGenerator>(address, trampoline, handler, content, metadata);
}

std::unique_ptr<WrapperGenerator> PosixArmV8Target::getWrapperGenerator(void* address, WrapperMetadata const& metadata) {
	return std::make_unique<ArmV8WrapperGenerator>(address, metadata);
}

#endif
