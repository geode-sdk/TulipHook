#include "Wrapper.hpp"

#include "platform/PlatformGenerator.hpp"

using namespace tulip::hook;

Wrapper& Wrapper::get() {
	static Wrapper ret;
	return ret;
}

Result<void*> Wrapper::createWrapper(void* address, WrapperMetadata const& metadata) {
	// TODO: make this use the wrapper functions from the conventions,
	// this is currently only for non windows

	if (m_wrappers.count(address) == 0) {
		// actually generate it here
		auto generator = PlatformWrapperGenerator(address, metadata);
		TULIP_HOOK_UNWRAP_INTO(auto wrapped, generator.generateWrapper());
		m_wrappers[address] = wrapped;
	}

	return Ok(m_wrappers[address]);
}