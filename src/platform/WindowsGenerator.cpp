#include "WindowsGenerator.hpp"
#include "PlatformTarget.hpp"
#include "../Handler.hpp"

#include <sstream>

#include <CallingConvention.hpp>
#include <iostream>

using namespace tulip::hook;

#if defined(TULIP_HOOK_WINDOWS)


namespace {
	void* TULIP_HOOK_DEFAULT_CONV preHandler(
		HandlerContent* content
	) {
		Handler::incrementIndex(content);
		auto ret = Handler::getNextFunction(content);

		return ret;
	}

	void TULIP_HOOK_DEFAULT_CONV postHandler() {
		Handler::decrementIndex();
	}
}

std::string WindowsGenerator::handlerString() {
	std::ostringstream out;
	out << std::hex;
	out << m_metadata.m_convention->generateToDefault(m_metadata.m_abstract) << "; ";

	// increment and get function
	out << R"ASM(
	push esi

	; set the parameters
	mov eax, [eip + _content]
	push eax
	
	; call the pre handler, incrementing
	mov eax, [eip + _handlerPre]
	call eax
)ASM";

	size_t stackSize = 0;
	for (auto& param : m_metadata.m_abstract.m_parameters) {
		stackSize += (param.m_size + 3) / 4 * 4;
	}
	// struct return
	if (m_metadata.m_abstract.m_return.m_size > 4 * 2) {
		stackSize += 4;
	}

	// push the stack params
	for (size_t i = 0; i < stackSize; i += 4) {
		out << "push [esp + 0x" << (stackSize + 8) << "]\n";
	}

	// call cdecl
	out << "call eax\n";

	// fix stack
	out << "add esp, 0x" << stackSize << "\n";
	
	// decrement and return eax and edx
	out << R"ASM(
	
	; preserve the return values
	sub esp, 0x28

	mov [esp + 0x24], edx
	mov [esp + 0x20], eax
	movaps [esp + 0x10], xmm1
	movaps [esp + 0x00], xmm0

	; call the post handler, decrementing
	mov eax, [eip + _handlerPost]
	call eax

	; recover the return values
	mov edx, [esp + 0x24]
	mov eax, [esp + 0x20]
	movaps xmm1, [esp + 0x10]
	movaps xmm0, [esp + 0x00]

	add esp, 0x28

	pop esi
)ASM";

	out << m_metadata.m_convention->generateFromDefault(m_metadata.m_abstract);
	
	out << R"ASM(
_handlerPre: 
	dd 0x)ASM" << reinterpret_cast<uint64_t>(preHandler);

	out << R"ASM(
_handlerPost: 
	dd 0x)ASM" << reinterpret_cast<uint64_t>(postHandler);

	out << R"ASM(
_content: 
	dd 0x)ASM" << reinterpret_cast<uint64_t>(m_content);


	return out.str();
}

std::string WindowsGenerator::trampolineString(size_t offset) {
	std::ostringstream out;
	out << m_metadata.m_convention->generateBackToDefault(m_metadata.m_abstract, 0x8) << "; ";
	out << "jmp _address" << m_address << "_" << offset;
	return out.str();
}

#endif
