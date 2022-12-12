#include "Pool.hpp"

#include "Handler.hpp"

using namespace tulip::hook;

Pool& Pool::get() {
	static Pool ret;
	return ret;
}

Result<HandlerHandle> Pool::createHandler(void* address, HandlerMetadata const& metadata) {
	auto handle = reinterpret_cast<HandlerHandle>(address);

	if (m_handlers.find(handle) == m_handlers.end()) {
		TULIP_HOOK_UNWRAP_INTO(auto handler, Handler::create(address, metadata));
		m_handlers.emplace(handle, std::move(handler));
		TULIP_HOOK_UNWRAP(m_handlers[handle]->init());
	}

	TULIP_HOOK_UNWRAP(m_handlers[handle]->interveneFunction());

	return Ok(std::move(handle));
}

Result<> Pool::removeHandler(HandlerHandle const& handle) {
	m_handlers[handle]->clearHooks();
	TULIP_HOOK_UNWRAP(m_handlers[handle]->restoreFunction());
	return Ok();
}

Handler& Pool::getHandler(HandlerHandle const& handle) {
	return *m_handlers.at(handle);
}
