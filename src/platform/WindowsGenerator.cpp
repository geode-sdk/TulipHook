#include "WindowsGenerator.hpp"
#include "PlatformTarget.hpp"
#include "../Handler.hpp"

#include <sstream>

#include <CallingConvention.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_WINDOWS)


namespace {
	void* TULIP_HOOK_DEFAULT_CONV preHandler(
		HandlerContent* content,
		void* originalReturn
	) {
		Handler::incrementIndex(content);
		auto ret = Handler::getNextFunction(content);
		Handler::pushData(originalReturn);

		return ret;
	}

	void* TULIP_HOOK_DEFAULT_CONV postHandler() {
		auto ret = Handler::popData();
		Handler::decrementIndex();
		return ret;
	}
}

std::string MacosGenerator::handlerString() {
	std::ostringstream out;
	// keystone uses hex by default
	out << std::hex;

	out << R"ASM(

	; preserve registers
	sub esp, 0x68

	mov [esp + 0x64], edx
	mov [esp + 0x60], ecx
	movaps [esp + 0x50], xmm5
	movaps [esp + 0x40], xmm4
	movaps [esp + 0x30], xmm3
	movaps [esp + 0x20], xmm2
	movaps [esp + 0x10], xmm1
	movaps [esp + 0x00], xmm0

	; preserve the original return
	mov eax, [esp + 0x68]

	; set the new return
	lea ecx, [eip + _handlerCont]
	mov [esp + 0x68], ecx

	; set the parameters
	mov ecx, [eip + _content]
	mov edx, eax

	; call the pre handler, incrementing
	mov eax, [eip + _handlerPre]
	call eax

	; recover registers
	mov edx, [esp + 0x64]
	mov ecx, [esp + 0x60]
	movaps xmm5, [esp + 0x50]
	movaps xmm4, [esp + 0x40]
	movaps xmm3, [esp + 0x30]
	movaps xmm2, [esp + 0x20]
	movaps xmm1, [esp + 0x10]
	movaps xmm0, [esp + 0x00]

	add esp, 0x68


	; call the func
	jmp eax

_handlerCont:
	sub esp, 0x8

	; preserve the return values
	sub esp, 0x28

	mov [esp + 0x24], edx
	mov [esp + 0x20], eax
	movaps [esp + 0x10], xmm1
	movaps [esp + 0x00], xmm0

	; call the post handler, decrementing
	mov eax, [eip + _handlerPost]
	call eax

	; recover the original return
	mov [esp + 0x28], eax

	; recover the return values
	mov edx, [esp + 0x24]
	mov eax, [esp + 0x20]
	movaps xmm1, [esp + 0x10]
	movaps xmm0, [esp + 0x00]

	add esp, 0x28
	
	; done!
	ret
)ASM";

	out << R"ASM(
_handlerPre: 
	dd 0x)ASM" << reinterpret_cast<uint64_t>(preHandler);

	out << R"ASM(
_handlerPost: 
	dd 0x)ASM" << reinterpret_cast<uint64_t>(postHandler);

	out << R"ASM(
_content: 
	dd 0x)ASM" << reinterpret_cast<uint64_t>(m_content);

	out << R"ASM(
_originalReturn: 
	dd 0x0)ASM";

	return out.str();
}

std::string WindowsGenerator::handlerString() {
	std::ostringstream out;
	out << std::hex;
	out << m_metadata.m_convention->generateToDefault(m_metadata.m_abstract) << "; ";

	// increment and get function
	out << "push esi; lea eax, [_content" << m_address << "]; push eax; call _incrementIndex; lea eax, [_content" << m_address << "]; push eax; call _getNextFunction; ";

	auto count = 0;
	for (auto& param : m_metadata.m_abstract.m_parameters) {
		count += (param.m_size + 3) / 4;
	}
	if (m_metadata.m_abstract.m_return.m_size > 4 * 2) ++count; // struct return

	// push the stack params
	for (auto i = 0; i < count; ++i) {
		out << "push [esp + " << ((count + 3) * 4) << "]; ";
	}

	// call cdecl
	out << "call eax; ";

	// fix stack
	out << "add esp, " << ((count + 2) * 4) << "; ";
	

	// decrement and return eax and edx
	out << "mov esi, eax; mov edi, edx; call _decrementIndex; mov edx, edi; mov eax, esi; pop esi; ";

	out << m_metadata.m_convention->generateFromDefault(m_metadata.m_abstract);
	return out.str();
}

#endif