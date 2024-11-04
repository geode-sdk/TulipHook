#include "Wrapper.hpp"

#include "target/PlatformTarget.hpp"

using namespace tulip::hook;

Wrapper& Wrapper::get() {
	static Wrapper ret;
	return ret;
}

geode::Result<void*> Wrapper::createWrapper(void* address, WrapperMetadata const& metadata) {
	if (m_wrappers.count(address) == 0) {
		auto generator = Target::get().getWrapperGenerator(address, metadata);
		GEODE_UNWRAP_INTO(auto wrapped, generator->generateWrapper());
		m_wrappers[address] = wrapped;
	}

	return geode::Ok(m_wrappers[address].m_address);
}

geode::Result<void*> Wrapper::createReverseWrapper(void* address, WrapperMetadata const& metadata) {
	if (m_reverseWrappers.count(address) == 0) {
		auto generator = Target::get().getWrapperGenerator(address, metadata);
		GEODE_UNWRAP_INTO(auto wrapped, generator->generateReverseWrapper());
		m_reverseWrappers[address] = wrapped;
	}

	return geode::Ok(m_reverseWrappers[address].m_address);
}
