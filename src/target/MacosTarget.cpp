#include "MacosTarget.hpp"

#include <Platform.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_MACOS)

Target& Target::get() {
	static MacosTarget ret;
	return ret;
}

Result<csh> MacosTarget::openCapstone() {
	cs_err status;

	status = cs_open(CS_ARCH_X86, CS_MODE_64, &m_capstone);
	if (status != CS_ERR_OK) {
		return Err("Couldn't open capstone");
	}

	return Ok(m_capstone);
}

std::unique_ptr<HandlerGenerator> MacosTarget::getHandlerGenerator(
	void* address, void* trampoline, void* handler, void* content, void* wrapped, HandlerMetadata const& metadata
) {
	return std::make_unique<X64HandlerGenerator>(address, trampoline, handler, content, wrapped, metadata);
}

std::unique_ptr<WrapperGenerator> MacosTarget::getWrapperGenerator(void* address, WrapperMetadata const& metadata) {
	return std::make_unique<X64WrapperGenerator>(address, metadata);
}

#endif