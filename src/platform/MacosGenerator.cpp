#include "MacosGenerator.hpp"
#include "PlatformTarget.hpp"
#include "../Handler.hpp"

#include <sstream>

#include <CallingConvention.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_MACOS)

void MacosGenerator::generateHandler() {

	auto ks = PlatformTarget::get().openKeystone();

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

	PlatformTarget::get().closeKeystone(ks);

}
std::vector<uint8_t> MacosGenerator::generateIntervener() {

	auto ks = PlatformTarget::get().openKeystone();

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

	std::vector<uint8_t> ret(encode, encode + size);

	ks_free(encode);

	PlatformTarget::get().closeKeystone(ks);

	return ret;
}
void MacosGenerator::generateTrampoline(size_t offset) {

	auto ks = PlatformTarget::get().openKeystone();

	size_t count;
	unsigned char* encode;
	size_t size;

	ks_option(ks, KS_OPT_SYM_RESOLVER, reinterpret_cast<size_t>(&Handler::symbolResolver));

	auto code = this->trampolineString(offset);
	auto address = reinterpret_cast<size_t>(m_trampoline) + offset;

	// std::cout << "handler: " << code << std::endl;
	auto status = ks_asm(ks, code.c_str(), address, &encode, &size, &count);
	if (status != KS_ERR_OK) {
		throw std::runtime_error("TulipHook - assembling trampoline failed");
	}

	std::memcpy(reinterpret_cast<void*>(address), encode, size);

	ks_free(encode);

	PlatformTarget::get().closeKeystone(ks);

}
size_t MacosGenerator::relocateOriginal(size_t target) {

	std::memcpy(m_trampoline, m_address, 32);
	size_t offset = 0;

	auto cs = PlatformTarget::get().openCapstone();

	cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

	auto insn = cs_malloc(cs);

	uint64_t address = reinterpret_cast<uint64_t>(m_trampoline);
	uint8_t const* code = reinterpret_cast<uint8_t const*>(m_trampoline);
	size_t size = 32;

	auto difference = reinterpret_cast<uint64_t>(m_trampoline) - reinterpret_cast<uint64_t>(m_address);

	auto targetAddress = address + target;

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
		}

		if (address >= targetAddress) break;
	}

	cs_free(insn, 1);

	PlatformTarget::get().closeCapstone(cs);

	return address - reinterpret_cast<uint64_t>(m_trampoline);
}


std::string MacosGenerator::handlerString() {
	std::ostringstream out;
	// out << "nop; nop; nop; nop; ";

	out << m_metadata.m_convention->generateToDefault(m_metadata.m_abstract) << "; ";

	// save regs
	out << "push rbp; push r15; push r14; push r13; push r12; push rbx; push rax; mov r14, r9; mov r15, r8; mov r12, rcx; mov r13, rdx; mov rbx, rsi; mov rbp, rdi; ";

	// increment and get function
	out << "lea rdi, [rip + _content" << m_address << "]; call _incrementIndex; lea rdi, [rip + _content" << m_address << "]; call _getNextFunction; ";

	auto count = 0;
	for (auto& param : m_metadata.m_abstract.m_parameters) {
		if (param.m_type == AbstractTypeType::Primitive) {
			count += std::max<size_t>(param.m_size, 8);
		}
		else count += 8;
	}
	if (m_metadata.m_abstract.m_return.m_size > 8 * 2) ++count; // struct return

	if (count % 2 == 1) {
		out << "sub rsp, 8; ";
	}

	out << "mov rdi, rbp; mov rsi, rbx; mov rdx, r13; mov rcx, r12; mov r8, r15; mov r9, r14; ";

	// push the stack params
	for (auto i = 6; i < count; ++i) {
		out << "mov rbp, [rsp + " << ((count + 1) * 8) << "]; push rbp; ";
	}

	// call 
	out << "call rax; ";

	if (count > 6) {
		auto fixup = ((count - 6) * 8);

		if (count % 2 == 1) {
			fixup += 8;
		}

		// fix stack
		out << "add rsp, " << fixup << "; ";
	}

	// decrement and return eax and edx
	out << "mov rbx, rax; mov r14, rdx; call _decrementIndex; mov rax, rbx; mov rdx, r14; add rsp, 8; pop rbx; pop r12; pop r13; pop r14; pop r15; pop rbp; ret; ";

	out << m_metadata.m_convention->generateFromDefault(m_metadata.m_abstract);
	return out.str();
}

std::string MacosGenerator::intervenerString() {
	std::ostringstream out;
	out << "jmp _handler" << m_address;
	return out.str();
}

std::string MacosGenerator::trampolineString(size_t offset) {
	std::ostringstream out;
	out << "jmp _address" << m_address << "_" << offset; 
	return out.str();
}

#endif