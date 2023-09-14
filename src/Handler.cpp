#include "Handler.hpp"

#include "Hook.hpp"
#include "Pool.hpp"
#include "Wrapper.hpp"
#include "target/PlatformTarget.hpp"

#include <algorithm>
#include <sstream>
#include <stack>

using namespace tulip::hook;

Handler::Handler(void* address, HandlerMetadata const& metadata) :
	m_address(address),
	m_metadata(metadata) {}

Result<std::unique_ptr<Handler>> Handler::create(void* address, HandlerMetadata const& metadata) {
	auto ret = std::make_unique<Handler>(address, metadata);

	TULIP_HOOK_UNWRAP_INTO(auto area1, Target::get().allocateArea(0x200));
	ret->m_content = static_cast<HandlerContent*>(area1);
	auto content = new (ret->m_content) HandlerContent();
	// std::cout << std::hex << "m_content: " << (void*)ret->m_content << std::endl;

	TULIP_HOOK_UNWRAP_INTO(ret->m_handler, Target::get().allocateArea(0x180));
	// std::cout << std::hex << "m_handler: " << (void*)ret->m_handler << std::endl;

	TULIP_HOOK_UNWRAP_INTO(ret->m_trampoline, Target::get().allocateArea(0x40));

	auto wrapperMetadata = WrapperMetadata{
		.m_convention = metadata.m_convention,
		.m_abstract = metadata.m_abstract,
	};
	TULIP_HOOK_UNWRAP_INTO(auto trampolineWrap, Wrapper::get().createWrapper(ret->m_trampoline, wrapperMetadata));
	ret->m_wrapped = trampolineWrap;
	// std::cout << std::hex << "m_trampoline: " << (void*)ret->m_trampoline << std::endl;

	return Ok(std::move(ret));
}

Handler::~Handler() {}

Result<> Handler::init() {
	// printf("func addr: 0x%" PRIx64 "\n", (uint64_t)m_address);

	auto generator =
		Target::get().getHandlerGenerator(m_address, m_trampoline, m_handler, m_content, m_wrapped, m_metadata);

	TULIP_HOOK_UNWRAP(generator->generateHandler());

	TULIP_HOOK_UNWRAP_INTO(m_modifiedBytes, generator->generateIntervener());

	auto target = m_modifiedBytes.size();

	auto address = reinterpret_cast<uint8_t*>(m_address);
	m_originalBytes.insert(m_originalBytes.begin(), address, address + target);

	TULIP_HOOK_UNWRAP_INTO(auto trampolineOffset, generator->relocateOriginal(target));
	TULIP_HOOK_UNWRAP(generator->generateTrampoline(trampolineOffset));

	auto metadata = HookMetadata();
	metadata.m_priority = INT32_MAX;
	static_cast<void>(this->createHook(m_wrapped, metadata));

	return Ok();
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

	auto metadata = HookMetadata{
		.m_priority = INT32_MAX,
	};
	static_cast<void>(this->createHook(m_wrapped, metadata));
}

void Handler::updateHookMetadata(HookHandle const& hook, HookMetadata const& metadata) {
	m_hooks.at(hook)->m_metadata = metadata;
	this->reorderFunctions();
}

void Handler::reorderFunctions() {
	auto& vec = m_content->m_functions;
	std::sort(vec.begin(), vec.end(), [this](auto const a, auto const b) {
		return (m_hooks.at(m_handles[a])->m_metadata.m_priority < m_hooks.at(m_handles[b])->m_metadata.m_priority);
	});
}

Result<> Handler::interveneFunction() {
	return Target::get().writeMemory(m_address, static_cast<void*>(m_modifiedBytes.data()), m_modifiedBytes.size());
}

Result<> Handler::restoreFunction() {
	return Target::get().writeMemory(m_address, static_cast<void*>(m_originalBytes.data()), m_originalBytes.size());
}

// TODO: fully remove the symbol resolver because i dont like it
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