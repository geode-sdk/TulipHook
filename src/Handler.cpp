#include "Handler.hpp"
#include "Hook.hpp"
#include "Pool.hpp"
#include "platform/PlatformTarget.hpp"
#include "platform/PlatformGenerator.hpp"

#include <stack>
#include <sstream>
#include <iostream>
#include <algorithm>

using namespace tulip::hook;

Handler::Handler(NoPublicConstruct, void* address, HandlerMetadata metadata)
  : m_address(address),
  	m_metadata(metadata) {}

Result<std::unique_ptr<Handler>> Handler::create(void* address, HandlerMetadata metadata) {
	auto ret = std::make_unique<Handler>(NoPublicConstruct(), address, metadata);

	TULIP_UNWRAP_INTO(auto area1, PlatformTarget::get().allocateArea(448));
	ret->m_content = reinterpret_cast<HandlerContent*>(area1);

	auto content = new (ret->m_content) HandlerContent();
	ret->m_handler = reinterpret_cast<void*>(reinterpret_cast<HandlerContent*>(area1) + 1);

	TULIP_UNWRAP_INTO(auto area2, PlatformTarget::get().allocateArea(64));
	ret->m_trampoline = area2;

	return Ok(std::move(ret));
}

Handler::~Handler() {
	
}

Result<> Handler::init() {
	// printf("func addr: 0x%" PRIx64 "\n", (uint64_t)m_address);

	auto generator = PlatformGenerator(m_address, m_trampoline, m_handler, m_content, m_metadata);

	TULIP_UNWRAP(generator.generateHandler());

	TULIP_UNWRAP_INTO(m_modifiedBytes, generator.generateIntervener());

	auto target = m_modifiedBytes.size();

	auto address = reinterpret_cast<uint8_t*>(m_address);
	m_originalBytes.insert(m_originalBytes.begin(), address, address + target);
	
	
	TULIP_UNWRAP_INTO(auto trampolineOffset, generator.relocateOriginal(target));
	TULIP_UNWRAP(generator.generateTrampoline(trampolineOffset));


	auto metadata = HookMetadata();
	metadata.m_priority = INT32_MAX;
	this->createHook(m_trampoline, metadata);

	return Ok();
}

HookHandle Handler::createHook(void* address, HookMetadata m_metadata) {
	auto hook = reinterpret_cast<HookHandle>(address);

	m_hooks.emplace(hook, std::make_unique<Hook>(address, m_metadata));
	m_content->m_functions[m_content->m_size] = address;
	++m_content->m_size;

	this->reorderFunctions();

	return hook;
}

void Handler::removeHook(HookHandle const& hook) {
	auto address = reinterpret_cast<void*>(hook);

	m_hooks.erase(hook);
	(void)std::remove(
		m_content->m_functions.data(),
		m_content->m_functions.data() + m_content->m_size,
		address
	);
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
		return (
			m_hooks.at(reinterpret_cast<HookHandle>(a))->m_metadata.m_priority <
			m_hooks.at(reinterpret_cast<HookHandle>(b))->m_metadata.m_priority
		);
	});
}

Result<> Handler::interveneFunction() {
	return PlatformTarget::get()
		.writeMemory(m_address, static_cast<void*>(m_modifiedBytes.data()), m_originalBytes.size());
}
Result<> Handler::restoreFunction() {
	return PlatformTarget::get()
		.writeMemory(m_address, static_cast<void*>(m_originalBytes.data()), m_originalBytes.size());
}


bool TULIP_HOOK_DEFAULT_CONV Handler::symbolResolver(char const* csymbol, uint64_t* value) {
	std::string symbol = csymbol;

	if (symbol.find("_address") != std::string::npos) {
		auto in = std::istringstream(symbol.substr(8));

		std::string input;
		std::getline(in, input, '_');
		HandlerHandle handler = std::stoll(input, nullptr, 16);
		std::getline(in, input, '_');
		size_t offset = std::stoll(input, nullptr, 10);

		*value = reinterpret_cast<uint64_t>(Pool::get().getHandler(handler).m_address) + offset;
		return true;
	}

	if (symbol.find("_handler") != std::string::npos) {
		auto in = std::istringstream(symbol.substr(8));

		std::string input;
		std::getline(in, input, '_');
		HandlerHandle handler = std::stoll(input, nullptr, 16);

		*value = reinterpret_cast<uint64_t>(Pool::get().getHandler(handler).m_handler);
		return true;
	}

	if (symbol.find("_content") != std::string::npos) {
		auto in = std::istringstream(symbol.substr(8));

		std::string input;
		std::getline(in, input, '_');
		HandlerHandle handler = std::stoll(input, nullptr, 16);

		*value = reinterpret_cast<uint64_t>(Pool::get().getHandler(handler).m_content);
		return true;
	}

	if (symbol.find("_incrementIndex") != std::string::npos) {
		*value = reinterpret_cast<uint64_t>(&Handler::incrementIndex);
		return true;
	}

	if (symbol.find("_decrementIndex") != std::string::npos) {
		*value = reinterpret_cast<uint64_t>(&Handler::decrementIndex);
		return true;
	}

	if (symbol.find("_getNextFunction") != std::string::npos) {
		*value = reinterpret_cast<uint64_t>(&Handler::getNextFunction);
		return true;
	}

	return false;
}


static thread_local std::stack<size_t> s_indexStack;
static thread_local std::stack<HandlerContent*> s_addressStack;

void TULIP_HOOK_DEFAULT_CONV Handler::incrementIndex(HandlerContent* content) {
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

void TULIP_HOOK_DEFAULT_CONV Handler::decrementIndex() {
	// printf("decrementIndex\n");
	if (s_indexStack.top() == 0) {
		s_addressStack.pop();
		s_indexStack.pop();
	}
	else {
		--s_indexStack.top();
	}
}

void* TULIP_HOOK_DEFAULT_CONV Handler::getNextFunction(HandlerContent* content) {
	// printf("getNextFunction - content addr: 0x%" PRIx64 " index: %lu\n", (uint64_t)content, s_indexStack.top() % content->m_size);
	auto ret = content->m_functions[s_indexStack.top() % content->m_size];
	// printf("getNextFunction - next func addr: 0x%" PRIx64 "\n", (uint64_t)ret);
	return ret;
}

