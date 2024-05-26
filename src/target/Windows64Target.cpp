#include "Windows64Target.hpp"

#include <memory>
#include <Platform.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_WINDOWS) && defined(TULIP_HOOK_X64)

Target& Target::get() {
	static Windows64Target ret;
	return ret;
}

Result<csh> Windows64Target::openCapstone() {
	cs_err status;

	status = cs_open(CS_ARCH_X86, CS_MODE_64, &m_capstone);
	if (status != CS_ERR_OK) {
		return Err("Couldn't open capstone");
	}

	return Ok(m_capstone);
}

std::unique_ptr<HandlerGenerator> Windows64Target::getHandlerGenerator(
	void* address, void* trampoline, void* handler, void* content, void* wrapped, HandlerMetadata const& metadata
) {
	return std::make_unique<X64HandlerGenerator>(address, trampoline, handler, content, wrapped, metadata);
}

std::unique_ptr<WrapperGenerator> Windows64Target::getWrapperGenerator(void* address, WrapperMetadata const& metadata) {
	return std::make_unique<X64WrapperGenerator>(address, metadata);
}

#endif