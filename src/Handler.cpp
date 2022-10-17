#include "Handler.hpp"
#include "Hook.hpp"
#include "Pool.hpp"
#include "platform/Target.hpp"

#include <stack>
#include <sstream>
#include <iostream>

using namespace tulip::hook;

Handler::Handler(void* address, HandlerMetadata metadata) : m_address(address), m_metadata(metadata) {
	
}

Handler::~Handler() {
	
}

void Handler::init() {
	// printf("func addr: 0x%" PRIx64 "\n", (uint64_t)m_address);
	this->generateHandler();

	this->generateIntervener();

	this->generateTrampoline();

	auto metadata = HookMetadata();
	metadata.m_priority = INT32_MAX;
	this->createHook(m_trampoline, metadata);
}

HookHandle Handler::createHook(void* address, HookMetadata m_metadata) {
	auto hook = reinterpret_cast<HookHandle>(address);

	m_hooks.insert({hook, std::make_unique<Hook>(address, m_metadata)});
	m_content->m_functions[m_content->m_size] = address;
	++m_content->m_size;

	this->reorderFunctions();

	return hook;
}

void Handler::removeHook(HookHandle const& hook) {
	auto address = reinterpret_cast<void*>(hook);

	m_hooks.erase(hook);
	std::remove(m_content->m_functions.data(), m_content->m_functions.data() + m_content->m_size, address);
	--m_content->m_size;
}

void Handler::clearHooks() {
	std::vector<HandlerHandle> handles;
	for (auto& [handle, hook] : m_hooks) {
		if (reinterpret_cast<void*>(handle) == m_trampoline) continue;
		handles.push_back(handle);
	}

	for (auto handle : handles) {
		this->removeHook(handle);
	}
}

void Handler::reorderFunctions() {
	std::sort(m_content->m_functions.data(), m_content->m_functions.data() + m_content->m_size, [this](auto const a, auto const b){
		return (m_hooks[reinterpret_cast<HookHandle>(a)]->m_metadata.m_priority <
			m_hooks[reinterpret_cast<HookHandle>(b)]->m_metadata.m_priority);
	});
}

void Handler::interveneFunction() {
	Target::get().writeMemory(m_address, static_cast<void*>(m_modifiedBytes.data()), m_originalBytes.size());
}
void Handler::restoreFunction() {
	Target::get().writeMemory(m_address, static_cast<void*>(m_originalBytes.data()), m_originalBytes.size());
}

static thread_local std::stack<size_t> s_indexStack;
static thread_local std::stack<HandlerContent*> s_addressStack;

void Handler::incrementIndex(HandlerContent* content) {
	// printf("incrementIndex - content addr: 0x%" PRIx64 "\n", (uint64_t)content);
	if (s_addressStack.size() == 0 || s_addressStack.top() != content) {
		// new entry
		s_addressStack.push(content);
		s_indexStack.push(0);
	}
	else {
		++s_indexStack.top();
	}

	// printf("incrementIndex - top: 0x%" PRIx64 "\n", (uint64_t)s_indexStack.top());
}

void Handler::decrementIndex() {
	// printf("decrementIndex\n");
	if (s_indexStack.top() == 0) {
		s_addressStack.pop();
		s_indexStack.pop();
	}
	else {
		--s_indexStack.top();
	}
}

void* Handler::getNextFunction(HandlerContent* content) {
	// printf("getNextFunction - content addr: 0x%" PRIx64 " index: %lu\n", (uint64_t)content, s_indexStack.top() % content->m_size);
	auto ret = content->m_functions[s_indexStack.top() % content->m_size];
	// printf("getNextFunction - next func addr: 0x%" PRIx64 "\n", (uint64_t)ret);
	return ret;
}

