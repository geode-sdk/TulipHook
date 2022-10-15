#include "Handler.hpp"
#include "Hook.hpp"
#include "Pool.hpp"
#include "platform/Target.hpp"

#include <stack>
#include <sstream>

using namespace tulip::hook;

Handler::Handler(void* address, HandlerMetadata metadata) : m_address(address), m_metadata(metadata) {
	this->generateHandler();

	this->generateIntervener();

	this->generateTrampoline();

	this->interveneFunction();
}

void Handler::generateHandler() {

}
void Handler::generateIntervener() {
	// generate intervener

	auto ks = Target::get().openKeystone();

	size_t count;
	unsigned char* encode;
	size_t size;

	auto code = this->intervenerString();
	auto status = ks_asm(ks, code.c_str(), reinterpret_cast<size_t>(m_address), &encode, &size, &count);
	if (status != KS_ERR_OK) {
		throw std::runtime_error("TulipHook - assembling intervener failed");
	}

	Target::get().closeKeystone(ks);
}

Handler::~Handler() {

}

HookHandle Handler::createHook(void* address, HookMetadata m_metadata) {
	auto hook = reinterpret_cast<HookHandle>(address);

	m_hooks.insert({hook, std::make_unique<Hook>(address, m_metadata)});

	return hook;
}

void Handler::removeHook(HookHandle const& hook) {
	m_hooks.erase(hook);
}

void Handler::reorderFunctions() {

}

void Handler::interveneFunction() {
	Target::get().writeMemory(m_address, static_cast<void*>(m_modifiedBytes.data()), m_originalBytes.size());
}
void Handler::restoreFunction() {
	Target::get().writeMemory(m_address, static_cast<void*>(m_originalBytes.data()), m_originalBytes.size());
}

static thread_local std::stack<size_t> s_indexStack;
static thread_local std::stack<HandlerContent*> s_addressStack;

bool Handler::symbolResolver(char const* csymbol, uint64_t* value) {
	std::string symbol = csymbol;

	if (symbol.find("_address") != std::string::npos) {
		auto in = std::istringstream(symbol.substr(8));

		HandlerHandle handler;
		in >> std::hex >> handler;

		*value = reinterpret_cast<uint64_t>(Pool::get().getHandler(handler).m_address);

		return true;
	}

	if (symbol.find("_handler") != std::string::npos) {
		auto in = std::istringstream(symbol.substr(8));

		HandlerHandle handler;
		in >> std::hex >> handler;

		*value = reinterpret_cast<uint64_t>(Pool::get().getHandler(handler).m_handler);

		return true;
	}

	if (symbol.find("_content") != std::string::npos) {
		auto in = std::istringstream(symbol.substr(8));

		HandlerHandle handler;
		in >> std::hex >> handler;

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

void Handler::incrementIndex(HandlerContent* content) {
	if (s_addressStack.top() != content) {
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
	return content->m_functions[s_indexStack.top() % content->m_size];
}

