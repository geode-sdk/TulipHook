#include "Pool.hpp"
#include "Handler.hpp"

using namespace tulip::hook;

Pool& Pool::get() {
	static Pool ret;
	return ret;
}

HandlerHandle Pool::createHandler(void* address, HandlerMetadata m_metadata) {
	auto handle = reinterpret_cast<HandlerHandle>(address);

	if (m_handlers.find(handle) == m_handlers.end()) {
		m_handlers.insert({handle, std::make_unique<Handler>(address, m_metadata)});
		m_handlers[handle]->init();
	}

	m_handlers[handle]->interveneFunction();

	return handle;
}

void Pool::removeHandler(HandlerHandle const& handle) {
	m_handlers[handle]->clearHooks();
	m_handlers[handle]->restoreFunction();
}

Handler& Pool::getHandler(HandlerHandle const& handle) {
	return *m_handlers.at(handle);
}