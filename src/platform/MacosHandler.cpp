#include "../Handler.hpp"
#include <Platform.hpp>
#include <CallingConvention.hpp>

#include <sstream>
#include <array>

using namespace tulip::hook;

#if defined(TULIP_HOOK_MACOS)

std::string Handler::handlerString() {
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

std::string Handler::intervenerString() {
	std::ostringstream out;
	out << "jmp _handler" << m_address;
	return out.str();
}

std::string Handler::trampolineString(size_t offset) {
	std::ostringstream out;
	out << "jmp _address" << m_address << "_" << offset; 
	return out.str();
}

#endif