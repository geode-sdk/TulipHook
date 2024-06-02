#include "Handler.hpp"

#include "Hook.hpp"
#include "Pool.hpp"
#include "Wrapper.hpp"
#include "target/PlatformTarget.hpp"

#include <algorithm>
#include <sstream>
#include <stack>
#include <iostream>

using namespace tulip::hook;

Handler::Handler(void* address, HandlerMetadata const& metadata) :
	m_address(address),
	m_metadata(metadata) {}

Result<std::unique_ptr<Handler>> Handler::create(void* address, HandlerMetadata const& metadata) {
	auto ret = std::make_unique<Handler>(address, metadata);

	ret->m_content = new (std::nothrow) HandlerContent();
	if (!ret->m_content) {
		return Err("Failed to allocate HandlerContent");
	}
	std::cout << std::hex << "m_content: " << (void*)ret->m_content << std::endl;

	TULIP_HOOK_UNWRAP_INTO(ret->m_handler, Target::get().allocateArea(0x300));
	std::cout << std::hex << "m_handler: " << (void*)ret->m_handler << std::endl;

	TULIP_HOOK_UNWRAP_INTO(ret->m_trampoline, Target::get().allocateArea(0x100));

	// auto wrapperMetadata = WrapperMetadata{
	// 	.m_convention = metadata.m_convention,
	// 	.m_abstract = metadata.m_abstract,
	// };
	std::cout << std::hex << "m_trampoline: " << (void*)ret->m_trampoline << std::endl;

	return Ok(std::move(ret));
}

Handler::~Handler() {}

Result<> Handler::init() {
	// printf("func addr: 0x%" PRIx64 "\n", (uint64_t)m_address);

	auto generator =
		Target::get().getHandlerGenerator(m_address, m_trampoline, m_handler, m_content, m_metadata);

	TULIP_HOOK_UNWRAP(generator->generateHandler());
	std::cout << "generate handler" << std::endl;

	TULIP_HOOK_UNWRAP_INTO(m_modifiedBytes, generator->generateIntervener());
	std::cout << "generate intervener" << std::endl;

	auto target = m_modifiedBytes.size();

	auto address = reinterpret_cast<uint8_t*>(Target::get().getRealPtr(m_address));
	m_originalBytes.insert(m_originalBytes.begin(), address, address + target);
	std::cout << "add original bytes" << std::endl;

	TULIP_HOOK_UNWRAP(generator->generateTrampoline(target));
	std::cout << "generate trampoline" << std::endl;

	this->addOriginal();

	return Ok();
}

void Handler::addOriginal() {
	auto metadata = HookMetadata{
		.m_priority = INT32_MAX,
	};
	static_cast<void>(this->createHook(Target::get().getRealPtrAs(m_trampoline, m_address), metadata));
}

HookHandle Handler::createHook(void* address, HookMetadata m_metadata) {
	std::cout << "createHook: " << address << std::endl;
	static size_t s_nextHookHandle = 0;
	auto hook = HookHandle(++s_nextHookHandle);

	m_hooks.emplace(hook, std::make_unique<Hook>(address, m_metadata));
	m_handles.insert({address, hook});

	std::cout << "before functions size " << m_content->m_functions.size() << std::endl;
	m_content->m_functions.push_back(address);

	this->reorderFunctions();

	return hook;
}

void Handler::removeHook(HookHandle const& hook) {
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
	m_hooks.at(hook)->m_metadata = metadata;
	this->reorderFunctions();
}

void Handler::reorderFunctions() {
	auto& vec = m_content->m_functions;
	std::cout << "functions size " << vec.size() << std::endl;
	// std::sort(vec.begin(), vec.end(), [this](auto const a, auto const b) {
	// 	std::cout << "reordering " << m_handles[a] << " " << m_handles[b] << std::endl;
	// 	return (m_hooks.at(m_handles[a])->m_metadata.m_priority < m_hooks.at(m_handles[b])->m_metadata.m_priority);
	// });
	std::cout << "sorted\n";
}

Result<> Handler::interveneFunction() {
	return Target::get().writeMemory(
		Target::get().getRealPtr(m_address),
		static_cast<void*>(m_modifiedBytes.data()),
		m_modifiedBytes.size()
	);
}

Result<> Handler::restoreFunction() {
	return Target::get().writeMemory(
		Target::get().getRealPtr(m_address),
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