#include "Wrapper.hpp"

#include "target/PlatformTarget.hpp"

using namespace tulip::hook;

Wrapper& Wrapper::get() {
	static Wrapper ret;
	return ret;
}

Result<void*> Wrapper::createWrapper(void* address, WrapperMetadata const& metadata) {
	if (m_wrappers.count(address) == 0) {
		auto generator = Target::get().getWrapperGenerator(address, metadata);
		TULIP_HOOK_UNWRAP_INTO(auto wrapped, generator->generateWrapper());
		m_wrappers[address] = wrapped;
	}

	return Ok(m_wrappers[address]);
}

Result<void*> Wrapper::createReverseWrapper(void* address, WrapperMetadata const& metadata) {
	if (m_reverseWrappers.count(address) == 0) {
		auto generator = Target::get().getWrapperGenerator(address, metadata);
		TULIP_HOOK_UNWRAP_INTO(auto wrapped, generator->generateReverseWrapper());
		m_reverseWrappers[address] = wrapped;
	}

	return Ok(m_reverseWrappers[address]);
}
