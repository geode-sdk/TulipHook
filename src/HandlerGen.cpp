#include "Handler.hpp"
#include "platform/Target.hpp"

using namespace tulip::hook;

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