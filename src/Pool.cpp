#include "Pool.hpp"

#include "Handler.hpp"
#include "target/Target.hpp"
#include <tulip/platform/DefaultConvention.hpp>

using namespace tulip::hook;

Pool& Pool::get() {
	static Pool ret;
	return ret;
}

geode::Result<HandlerHandle> Pool::createHandler(void* address, HandlerMetadata const& metadata) {
	auto handle = reinterpret_cast<HandlerHandle>(address);

	if (m_handlers.find(handle) == m_handlers.end()) {
		auto handler = Handler::create(address, metadata);
		m_handlers.emplace(handle, std::move(handler));

		if (!m_runtimeInterveningDisabled) {
			GEODE_UNWRAP(m_handlers[handle]->init());
			GEODE_UNWRAP(m_handlers[handle]->interveneFunction());
		}
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

void* Pool::getCommonHandler(void* originalFunction, size_t uniqueIndex, ptrdiff_t trampolineOffset, void* commonHandler, int handlerType) {
	if (handlerType == 1) {
		Handler::decrementIndex();
		return nullptr;
	}

	if (m_handlerList.size() <= uniqueIndex || m_handlerList[uniqueIndex] == nullptr) {
		m_handlerList.resize(uniqueIndex + 1, nullptr);

		auto handle = reinterpret_cast<HandlerHandle>(originalFunction);
		if (m_handlers.find(handle) == m_handlers.end()) {
			auto handler = Handler::create(originalFunction, HandlerMetadata{
				.m_convention = std::make_shared<DefaultConvention>(),
				.m_abstract = AbstractFunction::from<void(void)>()
			});
			m_handlers.emplace(handle, std::move(handler));
		}
		m_handlerList[uniqueIndex] = m_handlers[handle].get();

		auto trampoline = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(commonHandler) + trampolineOffset);

		auto metadata = HookMetadata{
			.m_priority = INT_MAX,
		};
		m_handlerList[uniqueIndex]->createHook(trampoline, metadata);
	}

	auto handler = m_handlerList[uniqueIndex];
	auto content = handler->m_content.get();
	Handler::incrementIndex(content);
	return Handler::getNextFunction(content);
}

void* Pool::getCommonHandlerStatic(void* originalFunction, size_t uniqueIndex, ptrdiff_t trampolineOffset, void* commonHandler, int handlerType) {
	return Pool::get().getCommonHandler(originalFunction, uniqueIndex, trampolineOffset, commonHandler, handlerType	);
}

geode::Result<> Pool::disableRuntimeIntervening(void* commonHandlerSpace) {
	if (m_runtimeInterveningDisabled) {
		return geode::Ok();
	}

	if (!commonHandlerSpace) {
		return geode::Err("Common handler space is null");
	}

	auto handler = reinterpret_cast<void*>(&Pool::getCommonHandlerStatic);
	GEODE_UNWRAP(Target::get().rawWriteMemory(commonHandlerSpace, &handler, sizeof(handler)));

	m_runtimeInterveningDisabled = true;
	
	return geode::Ok();
}