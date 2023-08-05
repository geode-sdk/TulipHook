#include "MacosGenerator.hpp"

#include "../Handler.hpp"
#include "../assembler/X64Assembler.hpp"
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

std::vector<uint8_t> MacosHandlerGenerator::handlerBytes(uint64_t address) {
	X64Assembler a(address);
	RegMem64 m;
	using enum X64Register;

	for (size_t i = 0; i < 8; ++i) {
		a.nop();
	}

	// preserve registers
	a.sub(RSP, 0xb8);

	a.mov(m[RSP + 0xa8], R9);
	a.mov(m[RSP + 0xa0], R8);
	a.mov(m[RSP + 0x98], RCX);
	a.mov(m[RSP + 0x90], RDX);
	a.mov(m[RSP + 0x88], RSI);
	a.mov(m[RSP + 0x80], RDI);
	a.movaps(m[RSP + 0x70], XMM7);
	a.movaps(m[RSP + 0x60], XMM6);
	a.movaps(m[RSP + 0x50], XMM5);
	a.movaps(m[RSP + 0x40], XMM4);
	a.movaps(m[RSP + 0x30], XMM3);
	a.movaps(m[RSP + 0x20], XMM2);
	a.movaps(m[RSP + 0x10], XMM1);
	a.movaps(m[RSP + 0x00], XMM0);

	// preserve the original return
	a.mov(RAX, m[RSP + 0xb8]);

	// set the new return
	a.lea(RDI, "handlerCont");
	a.mov(m[RSP + 0xb8], RDI);

	// set the parameters
	a.mov(RDI, "content");
	a.mov(RSI, RAX);

	// call the pre handler, incrementing
	a.mov(RAX, "handlerPre");
	a.call(RAX);

	// recover registers
	a.movaps(XMM0, m[RSP + 0x00]);
	a.movaps(XMM1, m[RSP + 0x10]);
	a.movaps(XMM2, m[RSP + 0x20]);
	a.movaps(XMM3, m[RSP + 0x30]);
	a.movaps(XMM4, m[RSP + 0x40]);
	a.movaps(XMM5, m[RSP + 0x50]);
	a.movaps(XMM6, m[RSP + 0x60]);
	a.movaps(XMM7, m[RSP + 0x70]);
	a.mov(RDI, m[RSP + 0x80]);
	a.mov(RSI, m[RSP + 0x88]);
	a.mov(RDX, m[RSP + 0x90]);
	a.mov(RCX, m[RSP + 0x98]);
	a.mov(R8, m[RSP + 0xa0]);
	a.mov(R9, m[RSP + 0xa8]);

	a.add(RSP, 0xb8);

	// call the func
	a.jmp(RAX);

	a.label("handlerCont");

	a.sub(RSP, 0x8);

	// preserve the return values
	a.sub(RSP, 0x38);

	a.mov(m[RSP + 0x28], RDX);
	a.mov(m[RSP + 0x20], RAX);
	a.movaps(m[RSP + 0x10], XMM1);
	a.movaps(m[RSP + 0x00], XMM0);

	// call the post handler, decrementing
	a.mov(RAX, "handlerPost");
	a.call(RAX);

	// recover the original return
	a.mov(m[RSP + 0x38], RAX);

	// recover the return values
	a.movaps(XMM0, m[RSP + 0x00]);
	a.movaps(XMM1, m[RSP + 0x10]);
	a.mov(RAX, m[RSP + 0x20]);
	a.mov(RDX, m[RSP + 0x28]);

	a.add(RSP, 0x38);

	a.label("handlerPre");
	a.write64(reinterpret_cast<uint64_t>(preHandler));

	a.label("handlerPost");
	a.write64(reinterpret_cast<uint64_t>(postHandler));

	a.label("content");
	a.write64(reinterpret_cast<uint64_t>(m_content));

	a.updateLabels();

	return std::move(a.m_buffer);
}

std::string MacosHandlerGenerator::handlerString() {
	std::ostringstream out;
	// keystone uses hex by default
	out << std::hex;
	out << R"ASM(
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
)ASM";
	out << m_metadata.m_convention->generateIntoDefault(m_metadata.m_abstract) << "\n ";

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
)ASM";

	out << m_metadata.m_convention->generateDefaultCleanup(m_metadata.m_abstract);

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

std::vector<uint8_t> MacosHandlerGenerator::intervenerBytes(uint64_t address) {
	X64Assembler a(address);
	RegMem64 m;
	using enum X64Register;

	a.jmp(reinterpret_cast<uint64_t>(m_handler));

	return std::move(a.m_buffer);
}

std::vector<uint8_t> MacosHandlerGenerator::trampolineBytes(uint64_t address, size_t offset) {
	X64Assembler a(address);
	RegMem64 m;
	using enum X64Register;

	a.jmp(reinterpret_cast<uint64_t>(m_address) + offset);

	return std::move(a.m_buffer);
}

std::string MacosHandlerGenerator::trampolineString(size_t offset) {
	std::ostringstream out;
	out << "jmp _address" << m_address << "_" << offset;
	return out.str();
}

std::string MacosWrapperGenerator::wrapperString() {
	return "";
}

Result<void*> MacosWrapperGenerator::generateWrapper() {
	return Ok(m_address); // only windows needs the wrapper
}

std::string MacosWrapperGenerator::reverseWrapperString() {
	return "";
}

Result<void*> MacosWrapperGenerator::generateReverseWrapper() {
	return Ok(m_address); // only windows needs the wrapper
}

std::vector<uint8_t> MacosWrapperGenerator::wrapperBytes(uint64_t address) {
	return std::vector<uint8_t>();
}

std::vector<uint8_t> MacosWrapperGenerator::reverseWrapperBytes(uint64_t address) {
	return std::vector<uint8_t>();
}

#endif