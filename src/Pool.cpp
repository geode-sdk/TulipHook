#include "Pool.hpp"

#include "Handler.hpp"

using namespace tulip::hook;

Pool& Pool::get() {
	static Pool ret;
	return ret;
}

geode::Result<HandlerHandle> Pool::createHandler(void* address, HandlerMetadata const& metadata) {
	auto handle = reinterpret_cast<HandlerHandle>(address);

	if (m_handlers.find(handle) == m_handlers.end()) {
		GEODE_UNWRAP_INTO(auto handler, Handler::create(address, metadata));
		m_handlers.emplace(handle, std::move(handler));
		GEODE_UNWRAP(m_handlers[handle]->init());
	}

	GEODE_UNWRAP(m_handlers[handle]->interveneFunction());

	return geode::Ok(std::move(handle));
}

geode::Result<> Pool::removeHandler(HandlerHandle const& handle) {
	m_handlers[handle]->clearHooks();
	GEODE_UNWRAP(m_handlers[handle]->restoreFunction());
	return geode::Ok();
}

Handler& Pool::getHandler(HandlerHandle const& handle) {
	return *m_handlers.at(handle);
}
