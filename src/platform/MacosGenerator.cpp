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

	// done!
	a.ret();

	a.label("handlerPre");
	a.write64(reinterpret_cast<uint64_t>(preHandler));

	a.label("handlerPost");
	a.write64(reinterpret_cast<uint64_t>(postHandler));

	a.label("content");
	a.write64(reinterpret_cast<uint64_t>(m_content));

	a.updateLabels();

	return std::move(a.m_buffer);
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

Result<void*> MacosWrapperGenerator::generateWrapper() {
	return Ok(m_address); // only windows needs the wrapper
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