#include "Handler.hpp"

#include "Hook.hpp"
#include "Pool.hpp"
#include "Wrapper.hpp"
#include "target/PlatformTarget.hpp"
#include <tulip/CallingConvention.hpp>

#include <algorithm>
#include <stack>
#include <iostream>
#include <iomanip>

using namespace tulip::hook;

Handler::Handler(void* address, HandlerMetadata const& metadata) :
	m_address(address),
	m_metadata(metadata),
	m_content(std::make_unique<HandlerContent>()),
	m_wrapperMetadata{metadata.m_convention, metadata.m_abstract} {

}

std::unique_ptr<Handler> Handler::create(void* address, HandlerMetadata const& metadata) {
	auto ret = std::make_unique<Handler>(address, metadata);
	return ret;
}

Handler::~Handler() {}

geode::Result<> Handler::init() {
	// printf("func addr: 0x%" PRIx64 "\n", (uint64_t)m_address);

	auto generator = Target::get().getGenerator();
	auto realAddress = Target::get().getRealPtr(m_address);

	// std::cout << std::noshowbase << std::setfill('0') << std::hex;

	auto dryHandler = generator->handlerBytes((int64_t)m_address, 0, m_content.get(), m_metadata);
	std::vector<uint8_t> handler;
	do {
		GEODE_UNWRAP_INTO(m_handler, Target::get().allocateArea(dryHandler.size()));
		handler = generator->handlerBytes((int64_t)m_address, (int64_t)m_handler, m_content.get(), m_metadata);

		if (handler.size() <= dryHandler.size()) break;

		dryHandler = std::move(handler);
	} while (true);
	// std::cout << m_handler << " Handler: " << std::endl;
	// for (auto c : handler) {
	// 	std::cout << std::setw(2) << +c << ' ';
	// }
	// std::cout << std::endl;
	GEODE_UNWRAP(Target::get().writeMemory(m_handler, handler.data(), handler.size()));
	m_handlerSize = handler.size();

	auto dryIntervener = generator->intervenerBytes(realAddress, (int64_t)m_handler, 0);

	GEODE_UNWRAP_INTO(auto dryRelocated, generator->relocatedBytes(realAddress, 0, dryIntervener.size()));
	BaseGenerator::RelocateReturn relocated;
	do {
		GEODE_UNWRAP_INTO(m_relocated, Target::get().allocateArea(dryRelocated.bytes.size()));
		GEODE_UNWRAP_INTO(relocated, generator->relocatedBytes(realAddress, (int64_t)m_relocated, dryIntervener.size()));

		if (handler.size() <= dryHandler.size()) break;

		dryHandler = std::move(handler);
	} while (true);
	// std::cout << m_relocated << " Relocated: " << std::endl;
	// for (auto c : relocated.bytes) {
	// 	std::cout << std::setw(2) << +c << ' ';
	// }
	// std::cout << std::endl;
	GEODE_UNWRAP(Target::get().writeMemory(m_relocated, relocated.bytes.data(), relocated.bytes.size()));

	if (m_metadata.m_convention->needsWrapper(m_metadata.m_abstract)) {
		auto dryWrapped = generator->wrapperBytes((int64_t)m_relocated, 0, m_wrapperMetadata);
		std::vector<uint8_t> wrapped;
		do {
			GEODE_UNWRAP_INTO(m_trampoline, Target::get().allocateArea(dryHandler.size()));
			wrapped = generator->wrapperBytes((int64_t)m_relocated, (int64_t)m_trampoline, m_wrapperMetadata);

			if (wrapped.size() <= dryWrapped.size()) break;

			dryWrapped = std::move(wrapped);
		} while (true);
		// std::cout << m_trampoline << " Trampoline: " << std::endl;
		// for (auto c : wrapped) {
		// 	std::cout << std::setw(2) << +c << ' ';
		// }
		// std::cout << std::endl;
		GEODE_UNWRAP(Target::get().writeMemory(m_trampoline, wrapped.data(), wrapped.size()));
		m_trampolineSize = wrapped.size();
	}
	else {
		m_trampoline = m_relocated;
	}
	

	m_modifiedBytes = generator->intervenerBytes(realAddress, (int64_t)m_handler, relocated.offset);
	// std::cout << m_address << " Intervener: " << std::endl;
	// for (auto c : m_modifiedBytes) {
	// 	std::cout << std::setw(2) << +c << ' ';
	// }
	// std::cout << std::endl;

	auto target = m_modifiedBytes.size();

	m_originalBytes.insert(m_originalBytes.begin(), m_modifiedBytes.size(), 0);
	GEODE_UNWRAP(Target::get().writeMemory(m_originalBytes.data(), (void*)realAddress, m_originalBytes.size()));
	// std::cout << m_address << " Original: " << std::endl;
	// for (auto c : m_originalBytes) {
	// 	std::cout << std::setw(2) << +c << ' ';
	// }
	// std::cout << std::endl;

	this->addOriginal();

	return geode::Ok();
}

void Handler::addOriginal() {
	auto metadata = HookMetadata{
		.m_priority = INT32_MAX,
	};
	static_cast<void>(this->createHook((void*)Target::get().getRealPtrAs(m_trampoline, m_address), metadata));
}

HookHandle Handler::createHook(void* address, HookMetadata m_metadata) {
	static size_t s_nextHookHandle = 0;
	auto hook = HookHandle(++s_nextHookHandle);

	m_hooks.emplace(hook, std::make_unique<Hook>(address, m_metadata));
	m_handles.insert({address, hook});

	m_content->m_functions.push_back(address);

	this->reorderFunctions();

	return hook;
}

void Handler::removeHook(HookHandle const& hook) {
	if (m_hooks.count(hook) == 0) {
		return;
	}
	auto address = m_hooks[hook]->m_address;

	m_hooks.erase(hook);
	m_handles.erase(address);

	auto& vec = m_content->m_functions;

	vec.erase(std::remove(vec.begin(), vec.end(), address), vec.end());
}

void Handler::clearHooks() {
	m_hooks.clear();
	m_handles.clear();
	m_content->m_functions.clear();

	this->addOriginal();
}

void Handler::updateHookMetadata(HookHandle const& hook, HookMetadata const& metadata) {
	if (m_hooks.count(hook) == 0) {
		return;
	}
	m_hooks.at(hook)->m_metadata = metadata;
	this->reorderFunctions();
}

void Handler::reorderFunctions() {
	auto& vec = m_content->m_functions;
	std::sort(vec.begin(), vec.end(), [this](auto const a, auto const b) {
		return (m_hooks.at(m_handles[a])->m_metadata.m_priority < m_hooks.at(m_handles[b])->m_metadata.m_priority);
	});
}

geode::Result<> Handler::interveneFunction() {
	if (Pool::get().m_runtimeInterveningDisabled) {
		return geode::Err("Runtime intervening is disabled");
	}
	return Target::get().writeMemory(
		(void*)Target::get().getRealPtr(m_address),
		static_cast<void*>(m_modifiedBytes.data()),
		m_modifiedBytes.size()
	);
}

geode::Result<> Handler::restoreFunction() {
	if (Pool::get().m_runtimeInterveningDisabled) {
		return geode::Err("Runtime intervening is disabled");
	}
	return Target::get().writeMemory(
		(void*)Target::get().getRealPtr(m_address),
		static_cast<void*>(m_originalBytes.data()),
		m_originalBytes.size()
	);
}

static thread_local std::stack<size_t> s_indexStack;
static thread_local std::stack<HandlerContent*> s_addressStack;
static thread_local std::stack<void*> s_dataStack;

void Handler::incrementIndex(HandlerContent* content) {
	if (s_addressStack.size() == 0 || s_addressStack.top() != content) {
		// new entry
		s_addressStack.push(content);
		s_indexStack.push(0);
	}
	else {
		++s_indexStack.top();
	}
}

void Handler::decrementIndex() {
	if (s_indexStack.top() == 0) {
		s_addressStack.pop();
		s_indexStack.pop();
	}
	else {
		--s_indexStack.top();
	}
}

void* Handler::getNextFunction(HandlerContent* content) {
	auto& vec = content->m_functions;
	auto ret = vec[s_indexStack.top() % vec.size()];
	return ret;
}

void* Handler::popData() {
	auto ret = s_dataStack.top();
	s_dataStack.pop();
	return ret;
}

void Handler::pushData(void* data) {
	s_dataStack.push(data);
}