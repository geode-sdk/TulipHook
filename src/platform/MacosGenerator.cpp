#include "MacosGenerator.hpp"

#include "../Handler.hpp"
#include "PlatformTarget.hpp"

#include <CallingConvention.hpp>
#include <sstream>

using namespace tulip::hook;

#if defined(TULIP_HOOK_MACOS)

namespace {
	void* TULIP_HOOK_DEFAULT_CONV preHandler(HandlerContent* content, void* originalReturn) {
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
	sub rsp, 0xb8

	mov [rsp + 0xa8], r9
	mov [rsp + 0xa0], r8
	mov [rsp + 0x98], rcx
	mov [rsp + 0x90], rdx
	mov [rsp + 0x88], rsi
	mov [rsp + 0x80], rdi
	movaps [rsp + 0x70], xmm7
	movaps [rsp + 0x60], xmm6
	movaps [rsp + 0x50], xmm5
	movaps [rsp + 0x40], xmm4
	movaps [rsp + 0x30], xmm3
	movaps [rsp + 0x20], xmm2
	movaps [rsp + 0x10], xmm1
	movaps [rsp + 0x00], xmm0

	; preserve the original return
	mov rax, [rsp + 0xb8]

	; set the new return
	lea rdi, [rip + _handlerCont]
	mov [rsp + 0xb8], rdi

	; set the parameters
	mov rdi, [rip + _content]
	mov rsi, rax

	; call the pre handler, incrementing
	mov rax, [rip + _handlerPre]
	call rax

	; recover registers
	mov r9, [rsp + 0xa8]
	mov r8, [rsp + 0xa0]
	mov rcx, [rsp + 0x98]
	mov rdx, [rsp + 0x90]
	mov rsi, [rsp + 0x88]
	mov rdi, [rsp + 0x80]
	movaps xmm7, [rsp + 0x70]
	movaps xmm6, [rsp + 0x60]
	movaps xmm5, [rsp + 0x50]
	movaps xmm4, [rsp + 0x40]
	movaps xmm3, [rsp + 0x30]
	movaps xmm2, [rsp + 0x20]
	movaps xmm1, [rsp + 0x10]
	movaps xmm0, [rsp + 0x00]

	add rsp, 0xb8


	; call the func
	jmp rax

_handlerCont:
	sub rsp, 0x8

	; preserve the return values
	sub rsp, 0x38

	mov [rsp + 0x28], rdx
	mov [rsp + 0x20], rax
	movaps [rsp + 0x10], xmm1
	movaps [rsp + 0x00], xmm0

	; call the post handler, decrementing
	mov rax, [rip + _handlerPost]
	call rax

	; recover the original return
	mov [rsp + 0x38], rax

	; recover the return values
	mov rdx, [rsp + 0x28]
	mov rax, [rsp + 0x20]
	movaps xmm1, [rsp + 0x10]
	movaps xmm0, [rsp + 0x00]

	add rsp, 0x38
	
	; done!
	ret
)ASM";

	out << R"ASM(
_handlerPre: 
	dq 0x)ASM"
		<< reinterpret_cast<uint64_t>(preHandler);

	out << R"ASM(
_handlerPost: 
	dq 0x)ASM"
		<< reinterpret_cast<uint64_t>(postHandler);

	out << R"ASM(
_content: 
	dq 0x)ASM"
		<< reinterpret_cast<uint64_t>(m_content);

	out << R"ASM(
_originalReturn: 
	dq 0x0)ASM";

	return out.str();
}

std::string MacosGenerator::trampolineString(size_t offset) {
	std::ostringstream out;
	out << "jmp _address" << m_address << "_" << offset;
	return out.str();
}

#endif