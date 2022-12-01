#include "MacosGenerator.hpp"
#include "PlatformTarget.hpp"
#include "../Handler.hpp"

#include <sstream>

#include <CallingConvention.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_MACOS)

namespace {
	inline auto align16(auto in) {
		return (((in + 15) / 16) * 16);
	}

	inline auto align8(auto in) {
		return (((in + 7) / 8) * 8);
	}
}

std::string MacosGenerator::handlerString() {
	std::ostringstream out;
	// keystone uses hex by default
	out << std::hex;

	// how many stack space is used by parameters
	auto totalCount = 0;
	auto floatingCount = 0;
	auto registerCount = 0;
	for (auto& param : m_metadata.m_abstract.m_parameters) {
		switch (param.m_type) {
			case AbstractTypeType::Primitive:
				registerCount += (param.m_size + 7) / 8;
				break;
			case AbstractTypeType::FloatingPoint:
				if (floatingCount < 8) ++floatingCount;
			default:
				++registerCount;
		}
	}
	if (m_metadata.m_abstract.m_return.m_size > 16) ++registerCount; // struct return

	auto stackCount = std::max(registerCount - 6, 0) + std::max(floatingCount - 8, 0);
	auto stackParamSize = 
	auto xmmStartOffset = align16(stackCount * 8) + 8;
	auto localSize = align16(floatingCount * 8 + xmmStartOffset) + 8;

	// function start
	out << "push rbp; push r15; push r14; push r13; push r12; push rbx; push rax; sub rsp, " << localSize << ";";

	// retain register parameters
	switch (registerCount) {
		default:
		case 6: 
			out << "mov r14, r9; ";
			[[fallthrough]];
		case 5:
			out << "mov r15, r8; ";
			[[fallthrough]];
		case 4:
			out << "mov r12, rcx; ";
			[[fallthrough]];
		case 3:
			out << "mov r13, rdx; ";
			[[fallthrough]];
		case 2:
			out << "mov rbx, rsi; ";
			[[fallthrough]];
		case 1:
			out << "mov rbp, rdi; ";
			[[fallthrough]];
	}

	// retain sse parameters
	for (auto i = std::min(floatingCount, 7); i > 0; --i) {
		out << "movsd qword ptr [rsp + " << xmmStartOffset + i * 8 << "], xmm" << i << "; ";
	}

	// increment and get function
	out << "lea rdi, [rip + _content" << m_address << "]; call _incrementIndex; lea rdi, [rip + _content" << m_address << "]; call _getNextFunction; ";


	// restore register parameters
	out << "mov rdi, rbp; mov rsi, rbx; mov rdx, r13; mov rcx, r12; mov r8, r15; mov r9, r14; ";

	// restore register parameters
	switch (registerCount) {
		default:
		case 6: 
			out << "mov r9, r14; ";
			[[fallthrough]];
		case 5:
			out << "mov r8, r15; ";
			[[fallthrough]];
		case 4:
			out << "mov rcx, r12; ";
			[[fallthrough]];
		case 3:
			out << "mov rdx, r13; ";
			[[fallthrough]];
		case 2:
			out << "mov rsi, rbx; ";
			[[fallthrough]];
		case 1:
			out << "mov rdi, rbp; ";
			[[fallthrough]];
	}

	auto oddAdd = totalCount % 2;
	static constexpr auto xmmAdd = 4;

	// push the stack parameters
	for (auto i = 6; i < totalCount; ++i) {
		out << "mov rbp, [rsp + " << ((totalCount + 1 + oddAdd + xmmAdd) * 8) << "]; push rbp; ";
	}

	// call 
	out << "call rax; ";

	if (totalCount > 6) {
		// fix stack
		out << "add rsp, " << ((totalCount - 6 + oddAdd + xmmAdd) * 8) << "; ";
	}

	// decrement and return eax and edx

	// retain returns
	out << "mov rbx, rax; mov r14, rdx; movaps xmmword ptr [rsp + 16], xmm0; movaps xmmword ptr [rsp], xmm1; "
	// decrease the function index
	<< "call _decrementIndex; " 
	// restore returns
	<< "movaps  xmm0, xmmword ptr [rsp + 16]; movaps  xmm1, xmmword ptr [rsp]; mov rax, rbx; mov rdx, r14; " 
	// function end
	<< "add rsp, 40; pop rbx; pop r12; pop r13; pop r14; pop r15; pop rbp ";
	return out.str();
}

#endif