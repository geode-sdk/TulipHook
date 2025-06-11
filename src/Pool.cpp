#include "Pool.hpp"

#include "Handler.hpp"
#include "target/Target.hpp"

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

	if (!m_runtimeInterveningDisabled) {
		GEODE_UNWRAP(m_handlers[handle]->interveneFunction());
	}
	
	return geode::Ok(std::move(handle));
}

geode::Result<HandlerHandle> Pool::createHandler(void* address, HandlerMetadata2 const& metadata) {
	auto handle = reinterpret_cast<HandlerHandle>(address);

	if (m_handlers.find(handle) == m_handlers.end()) {
		GEODE_UNWRAP_INTO(auto handler, Handler::create(address, metadata));
		m_handlers.emplace(handle, std::move(handler));
		GEODE_UNWRAP(m_handlers[handle]->init(metadata.m_originalBytes));
	}

	if (!m_runtimeInterveningDisabled) {
		GEODE_UNWRAP(m_handlers[handle]->interveneFunction());
	}

	return geode::Ok(std::move(handle));
}

geode::Result<> Pool::removeHandler(HandlerHandle const& handle) {
	if (m_handlers.find(handle) == m_handlers.end()) {
		return geode::Err("Handler not found");
	}
	m_handlers[handle]->clearHooks();
	GEODE_UNWRAP(m_handlers[handle]->restoreFunction());
	return geode::Ok();
}

Handler& Pool::getHandler(HandlerHandle const& handle) {
	return *m_handlers.at(handle);
}

void* Pool::getCommonHandler(void* originalFunction, size_t uniqueIndex) {
	if (m_handlerList.size() <= uniqueIndex || m_handlerList[uniqueIndex] == nullptr) {
		m_handlerList.resize(uniqueIndex + 1, nullptr);

		for (auto& [handle, handler] : m_handlers) {
			if (handler->m_address == originalFunction) {
				m_handlerList[uniqueIndex] = handler.get();
				break;
			}
		}
	}
	return m_handlerList[uniqueIndex]->m_handler;
}

void* Pool::getCommonHandlerStatic(void* originalFunction, size_t uniqueIndex) {
	return Pool::get().getCommonHandler(originalFunction, uniqueIndex);
}

geode::Result<> Pool::disableRuntimeIntervening(void* commonHandlerSpace) {
	if (m_runtimeInterveningDisabled) {
		return geode::Ok();
	}

	if (!commonHandlerSpace) {
		return geode::Err("Common handler space is null");
	}

	auto handler = reinterpret_cast<void*>(&Pool::getCommonHandlerStatic);
	GEODE_UNWRAP(Target::get().writeMemory(commonHandlerSpace, handler, sizeof(handler)));

	m_runtimeInterveningDisabled = true;
	
	return geode::Ok();
}