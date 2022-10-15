#include "Pool.hpp"
#include "Handler.hpp"

using namespace tulip::hook;

Pool& Pool::get() {
	static Pool ret;
	return ret;
}

HandlerHandle Pool::createHandler(void* address, HandlerMetadata m_metadata) {
	auto handler = reinterpret_cast<HandlerHandle>(address);

	m_handlers.insert({handler, std::make_unique<Handler>(address, m_metadata)});

	return handler;
}

void Pool::removeHandler(HandlerHandle const& handler) {
	m_handlers.erase(handler);
}

Handler& Pool::getHandler(HandlerHandle const& handler) {
	return *m_handlers.at(handler);
}