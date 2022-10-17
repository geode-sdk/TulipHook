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

void testFunc(HandlerContent* content) {
	Handler::incrementIndex(content);
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

void Handler::generateTrampoline() {
	auto area = Target::get().allocateArea(32);
	m_trampoline = area;
	// printf("tramp addr: 0x%" PRIx64 "\n", (uint64_t)m_trampoline);

	std::memcpy(m_trampoline, m_address, 32);
	size_t offset = 0;

	{
		auto cs = Target::get().openCapstone();

		cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

		auto insn = cs_malloc(cs);

		uint64_t address = reinterpret_cast<uint64_t>(m_trampoline);
		uint8_t const* code = reinterpret_cast<uint8_t const*>(m_trampoline);
		size_t size = 32;

		auto difference = reinterpret_cast<uint64_t>(m_trampoline) - reinterpret_cast<uint64_t>(m_address);

		auto target = address + m_originalBytes.size();

		while(cs_disasm_iter(cs, &code, &size, &address, insn)) {
			auto detail = insn->detail;

			if (detail->x86.encoding.disp_offset > 0) {
				if (detail->x86.encoding.disp_size == sizeof(int)) {
					int displaced = detail->x86.disp - difference;

					std::memcpy(
						reinterpret_cast<void*>(insn->address + detail->x86.encoding.disp_offset),
						&displaced, sizeof(int)
					);
				}
				else {
					throw std::runtime_error("Not supported, displacement didn't work");
				}
				

				// printf("\tDisplacement offset: %u  Displacement size: %u, Displacement: 0x%" PRIx64,
				// 	detail->x86.encoding.disp_offset, detail->x86.encoding.disp_size, detail->x86.disp);
				// printf("\n");
			}

			if (address >= target) break;
		}

		offset = address - reinterpret_cast<uint64_t>(m_trampoline);

		cs_free(insn, 1);

		Target::get().closeCapstone(cs);
	}


	{
		auto ks = Target::get().openKeystone();

		size_t count;
		unsigned char* encode;
		size_t size;

		ks_option(ks, KS_OPT_SYM_RESOLVER, reinterpret_cast<size_t>(&Handler::symbolResolver));

		auto code = this->trampolineString(offset);

		// std::cout << "handler: " << code << std::endl;
		auto status = ks_asm(ks, code.c_str(), reinterpret_cast<size_t>(m_trampoline) + offset, &encode, &size, &count);
		if (status != KS_ERR_OK) {
			throw std::runtime_error("TulipHook - assembling trampoline failed");
		}

		std::memcpy(reinterpret_cast<void*>(reinterpret_cast<size_t>(m_trampoline) + offset), 
			encode, size);

		ks_free(encode);

		Target::get().closeKeystone(ks);
	}
}

void Handler::generateHandler() {
	auto area = Target::get().allocateArea(480);

	m_content = reinterpret_cast<HandlerContent*>(area);

	// printf("content addr: 0x%" PRIx64 "\n", (uint64_t)m_content);
	// to reset the contents if there are any
	auto content = new (m_content) HandlerContent();

	m_handler = reinterpret_cast<void*>(reinterpret_cast<HandlerContent*>(area) + 1);

	// printf("handler addr: 0x%" PRIx64 "\n", (uint64_t)m_handler);

	auto ks = Target::get().openKeystone();

	size_t count;
	unsigned char* encode;
	size_t size;

	ks_option(ks, KS_OPT_SYM_RESOLVER, reinterpret_cast<size_t>(&Handler::symbolResolver));

	auto code = this->handlerString();

	// std::cout << "handler: " << code << std::endl;
	auto status = ks_asm(ks, code.c_str(), reinterpret_cast<size_t>(m_handler), &encode, &size, &count);
	if (status != KS_ERR_OK) {
		throw std::runtime_error("TulipHook - assembling handler failed");
	}

	std::memcpy(m_handler, encode, size);

	ks_free(encode);

	Target::get().closeKeystone(ks);

}
void Handler::generateIntervener() {

	auto ks = Target::get().openKeystone();

	size_t count;
	unsigned char* encode;
	size_t size;

	ks_option(ks, KS_OPT_SYM_RESOLVER, reinterpret_cast<size_t>(&Handler::symbolResolver));

	auto code = this->intervenerString();

	// std::cout << "intervener: " << code << std::endl;
	auto status = ks_asm(ks, code.c_str(), reinterpret_cast<size_t>(m_address), &encode, &size, &count);
	if (status != KS_ERR_OK) {
		throw std::runtime_error("TulipHook - assembling intervener failed");
	}

	m_modifiedBytes.insert(m_modifiedBytes.begin(), size, 0);
	std::memcpy(m_modifiedBytes.data(), encode, size);

	m_originalBytes.insert(m_originalBytes.begin(), size, 0);
	std::memcpy(m_originalBytes.data(), m_address, size);


	ks_free(encode);

	Target::get().closeKeystone(ks);
}

Handler::~Handler() {
	
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

bool Handler::symbolResolver(char const* csymbol, uint64_t* value) {
	std::string symbol = csymbol;

	if (symbol.find("_address") != std::string::npos) {
		auto in = std::istringstream(symbol.substr(8));

		std::string input;
		std::getline(in, input, '_');
		HandlerHandle handler = std::stoll(input, nullptr, 16);
		std::getline(in, input, '_');
		size_t offset = std::stoll(input, nullptr, 10);

		*value = reinterpret_cast<uint64_t>(Pool::get().getHandler(handler).m_address) + offset;
		// *value -= 4; //TODO: figure out why this is needed
		return true;
	}

	if (symbol.find("_handler") != std::string::npos) {
		auto in = std::istringstream(symbol.substr(8));

		std::string input;
		std::getline(in, input, '_');
		HandlerHandle handler = std::stoll(input, nullptr, 16);

		*value = reinterpret_cast<uint64_t>(Pool::get().getHandler(handler).m_handler);
		// *value -= 4; //TODO: figure out why this is needed

		// printf("got handler addr: 0x%" PRIx64 "\n", *value);
		return true;
	}

	if (symbol.find("_content") != std::string::npos) {
		auto in = std::istringstream(symbol.substr(8));

		std::string input;
		std::getline(in, input, '_');
		HandlerHandle handler = std::stoll(input, nullptr, 16);

		*value = reinterpret_cast<uint64_t>(Pool::get().getHandler(handler).m_content);
		// *value -= 4; //TODO: figure out why this is needed

		// printf("got content addr: 0x%" PRIx64 "\n", *value);
		return true;
	}

	if (symbol.find("_incrementIndex") != std::string::npos) {
		*value = reinterpret_cast<uint64_t>(&Handler::incrementIndex);
		// *value -= 4; //TODO: figure out why this is needed
		return true;
	}

	if (symbol.find("_decrementIndex") != std::string::npos) {
		*value = reinterpret_cast<uint64_t>(&Handler::decrementIndex);
		// *value -= 4; //TODO: figure out why this is needed
		return true;
	}

	if (symbol.find("_getNextFunction") != std::string::npos) {
		*value = reinterpret_cast<uint64_t>(&Handler::getNextFunction);
		// *value -= 4; //TODO: figure out why this is needed
		return true;
	}

	return false;
}

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

