#include "X64Generator.hpp"

#include "../Handler.hpp"
#include "../assembler/X64Assembler.hpp"
#include "../target/PlatformTarget.hpp"

#include <CallingConvention.hpp>
#include <sstream>
#include <iostream>

using namespace tulip::hook;

namespace {
	void* TULIP_HOOK_DEFAULT_CONV preHandler(HandlerContent* content) {
		Handler::incrementIndex(content);
		auto ret = Handler::getNextFunction(content);

		return ret;
	}

	void TULIP_HOOK_DEFAULT_CONV postHandler() {
		Handler::decrementIndex();
	}
}

size_t X64HandlerGenerator::preserveRegisters(X64Assembler& a) {
	using enum X64Register;
	RegMem64 m;
#ifdef TULIP_HOOK_WINDOWS
	constexpr auto PRESERVE_SIZE = 0x70;
	a.sub(RSP, PRESERVE_SIZE);

	a.mov(m[RSP + 0x58], R9);
	a.mov(m[RSP + 0x50], R8);
	a.mov(m[RSP + 0x48], RDX);
	a.mov(m[RSP + 0x40], RCX);
	a.movaps(m[RSP + 0x30], XMM3);
	a.movaps(m[RSP + 0x20], XMM2);
	a.movaps(m[RSP + 0x10], XMM1);
	a.movaps(m[RSP + 0x00], XMM0);
#else
	constexpr auto PRESERVE_SIZE = 0xc0;
	a.sub(RSP, PRESERVE_SIZE);

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
#endif
	return PRESERVE_SIZE;
}
void X64HandlerGenerator::restoreRegisters(X64Assembler& a, size_t size) {
	using enum X64Register;
	RegMem64 m;
#ifdef TULIP_HOOK_WINDOWS
	a.movaps(XMM0, m[RSP + 0x00]);
	a.movaps(XMM1, m[RSP + 0x10]);
	a.movaps(XMM2, m[RSP + 0x20]);
	a.movaps(XMM3, m[RSP + 0x30]);
	a.mov(RCX, m[RSP + 0x40]);
	a.mov(RDX, m[RSP + 0x48]);
	a.mov(R8, m[RSP + 0x50]);
	a.mov(R9, m[RSP + 0x58]);

	a.add(RSP, size);
#else
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

	a.add(RSP, size);
#endif
}

size_t X64HandlerGenerator::preserveReturnRegisters(X64Assembler& a) {
	using enum X64Register;
	RegMem64 m;
#ifdef TULIP_HOOK_WINDOWS
	constexpr auto PRESERVE_SIZE = 0x20;
	a.sub(RSP, PRESERVE_SIZE);

	a.movaps(m[RSP + 0x00], XMM0);
	a.mov(RSP + 0x10, RAX);
#else
	constexpr auto PRESERVE_SIZE = 0x30;
	a.sub(RSP, PRESERVE_SIZE);

	a.movaps(m[RSP + 0x00], XMM0);
	a.movaps(m[RSP + 0x10], XMM1);
	a.mov(RSP + 0x20, RAX);
	a.mov(RSP + 0x28, RDX);
#endif
	return PRESERVE_SIZE;
}
void X64HandlerGenerator::restoreReturnRegisters(X64Assembler& a, size_t size) {
	using enum X64Register;
	RegMem64 m;
#ifdef TULIP_HOOK_WINDOWS
	a.mov(RAX, m[RSP + 0x10]);
	a.movaps(XMM0, m[RSP + 0x00]);

	a.add(RSP, size);
#else
	a.mov(RDX, m[RSP + 0x28]);
	a.mov(RAX, m[RSP + 0x20]);
	a.movaps(XMM1, m[RSP + 0x10]);
	a.movaps(XMM0, m[RSP + 0x00]);

	a.add(RSP, size);
#endif
}

std::vector<uint8_t> X64HandlerGenerator::handlerBytes(uint64_t address) {
	X64Assembler a(address);
	RegMem64 m;
	using enum X64Register;

#ifdef TULIP_HOOK_WINDOWS
	constexpr auto FIRST_PARAM = RCX;
#else
	constexpr auto FIRST_PARAM = RDI;
#endif

	for (size_t i = 0; i < 8; ++i) {
		a.nop();
	}

	a.push(RBP);
	a.mov(RBP, RSP);
	a.sub(RSP, 0x10);
	// preserve registers
	const auto preservedSize = preserveRegisters(a);

	// set the parameters
	a.mov(FIRST_PARAM, "content");

	// call the pre handler, incrementing
	// a.callip("handlerPre");

	a.mov(m[RBP - 0x10], RAX);

	// recover registers
	restoreRegisters(a, preservedSize);

	// early test
	a.pop(RBP);
	a.ret();

	// call the func
	m_metadata.m_convention->generateIntoDefault(a, m_metadata.m_abstract);

	a.mov(RAX, m[RBP - 0x10]);
	// a.int3();
	a.call(RAX);
	// a.int3();
	m_metadata.m_convention->generateDefaultCleanup(a, m_metadata.m_abstract);

	// preserve the return values
	const auto returnPreservedSize = preserveReturnRegisters(a);

	// call the post handler, decrementing
	a.callip("handlerPost");

	// recover the return values
	restoreReturnRegisters(a, returnPreservedSize);

	// done!
	a.mov(RSP, RBP);
	a.pop(RBP);
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

std::vector<uint8_t> X64HandlerGenerator::intervenerBytes(uint64_t address) {
	X64Assembler a(address);
	RegMem64 m;
	using enum X64Register;

	auto difference = reinterpret_cast<int64_t>(m_handler) - static_cast<int64_t>(address) - 5;

	if (difference <= 0x7fffffffll && difference >= -0x80000000ll) {
		a.jmp(reinterpret_cast<uint64_t>(m_handler));
	}
	else {
		a.jmpip("handler");
		a.label("handler");
		a.write64(reinterpret_cast<uint64_t>(m_handler));

		a.updateLabels();
	}

	return std::move(a.m_buffer);
}


Result<> X64HandlerGenerator::relocateRIPInstruction(cs_insn* insn, uint8_t* buffer, uint64_t& trampolineAddress, uint64_t& originalAddress, int64_t disp) {
	auto const id = insn->id;
	auto const detail = insn->detail;
	auto const address = insn->address;
	auto const size = insn->size;
	auto const difference = static_cast<intptr_t>(trampolineAddress) - static_cast<intptr_t>(originalAddress);

	if (difference <= 0x7fffffffll && difference >= -0x80000000ll) {
		return X86HandlerGenerator::relocateRIPInstruction(insn, buffer, trampolineAddress, originalAddress, disp);
	}

	auto& operand0 = detail->x86.operands[0];
	X64Register reg;
	switch (operand0.reg) {
		using enum X64Register;
		case X86_REG_RAX: reg = RAX; break;
		case X86_REG_RCX: reg = RCX; break;
		case X86_REG_RDX: reg = RDX; break;
		case X86_REG_RBX: reg = RBX; break;
		case X86_REG_RSP: reg = RSP; break;
		case X86_REG_RBP: reg = RBP; break;
		case X86_REG_RSI: reg = RSI; break;
		case X86_REG_RDI: reg = RDI; break;
		case X86_REG_R8: reg = R8; break;
		case X86_REG_R9: reg = R9; break;
		case X86_REG_R10: reg = R10; break;
		case X86_REG_R11: reg = R11; break;
		case X86_REG_R12: reg = R12; break;
		case X86_REG_R13: reg = R13; break;
		case X86_REG_R14: reg = R14; break;
		case X86_REG_R15: reg = R15; break;
		default: goto fail;
	};

	if (id == X86_INS_MOV) {
		X64Assembler a(trampolineAddress);
		RegMem64 m;
		using enum X64Register;

		auto const absolute = static_cast<intptr_t>(originalAddress) + size + disp;

		a.mov(reg, "absolute-pointer");
		a.mov(reg, m[reg]);
		a.jmp("skip-pointer");

		a.label("absolute-pointer");
		a.write64(absolute);

		a.label("skip-pointer");

		a.updateLabels();

		auto bytes = std::move(a.m_buffer);
		std::memcpy(buffer, bytes.data(), bytes.size());

		trampolineAddress += bytes.size();
		originalAddress += size;
		return Ok();
	}
	if (id == X86_INS_LEA) {
		X64Assembler a(trampolineAddress);
		RegMem64 m;
		using enum X64Register;

		auto const absolute = static_cast<intptr_t>(originalAddress) + size + disp;

		a.mov(reg, "absolute-pointer");
		a.jmp("skip-pointer");

		a.label("absolute-pointer");
		a.write64(absolute);

		a.label("skip-pointer");

		a.updateLabels();

		auto bytes = std::move(a.m_buffer);
		std::memcpy(buffer, bytes.data(), bytes.size());

		trampolineAddress += bytes.size();
		originalAddress += size;
		return Ok();
	}
fail:
	return X86HandlerGenerator::relocateRIPInstruction(insn, buffer, trampolineAddress, originalAddress, disp);
}

std::vector<uint8_t> X64WrapperGenerator::wrapperBytes(uint64_t address) {
	X64Assembler a(address);
	using enum X64Register;

	a.push(RBP);
	a.mov(RBP, RSP);

	m_metadata.m_convention->generateIntoOriginal(a, m_metadata.m_abstract);

	auto difference = a.currentAddress() - reinterpret_cast<int64_t>(m_address) + 5;
	if (difference <= 0x7fffffffll && difference >= -0x80000000ll) {
		a.call(reinterpret_cast<uint64_t>(m_address));
	}
	else {
		a.callip("address");
	}

	m_metadata.m_convention->generateOriginalCleanup(a, m_metadata.m_abstract);

	a.pop(RBP);
	a.ret();

	a.label("address");
	a.write64(reinterpret_cast<uintptr_t>(m_address));

	a.updateLabels();

	return std::move(a.m_buffer);
}

// std::vector<uint8_t> X64WrapperGenerator::reverseWrapperBytes(uint64_t address) {
// 	X64Assembler a(address);
// 	using enum X64Register;

// 	m_metadata.m_convention->generateIntoDefault(a, m_metadata.m_abstract);

// 	a.mov(RAX, "address");
// 	a.call(RAX);

// 	m_metadata.m_convention->generateDefaultCleanup(a, m_metadata.m_abstract);

// 	a.label("address");
// 	a.write64(reinterpret_cast<uintptr_t>(m_address));

// 	a.updateLabels();

// 	return std::move(a.m_buffer);
// }

Result<> X64HandlerGenerator::generateTrampoline(uint64_t target) {
	X64Assembler a(reinterpret_cast<uint64_t>(m_trampoline));
	using enum X64Register;

	if (m_metadata.m_convention->needsWrapper(m_metadata.m_abstract)) {
		a.push(RBP);
		a.mov(RBP, RSP);
		m_metadata.m_convention->generateIntoOriginal(a, m_metadata.m_abstract);

		a.call("relocated");

		m_metadata.m_convention->generateOriginalCleanup(a, m_metadata.m_abstract);
		a.pop(RBP);
		a.ret();
	}

	a.label("relocated");

	TULIP_HOOK_UNWRAP_INTO(auto code, this->relocatedBytes(a.currentAddress(), target));

	a.m_buffer.insert(a.m_buffer.end(), code.m_relocatedBytes.begin(), code.m_relocatedBytes.end());

	auto difference = a.currentAddress() - reinterpret_cast<int64_t>(m_address) + 5 - code.m_originalOffset;

	// a.int3();
	if (difference <= 0x7fffffffll && difference >= -0x80000000ll) {
		a.jmp(reinterpret_cast<uint64_t>(m_address) + code.m_originalOffset);
	}
	else {
		a.jmpip("handler");

		a.label("handler");
		a.write64(reinterpret_cast<uint64_t>(m_address) + code.m_originalOffset);
	}
	// a.int3();

	a.updateLabels();

	auto codeSize = a.m_buffer.size();
	auto areaSize = (codeSize + (0x20 - codeSize) % 0x20);

	TULIP_HOOK_UNWRAP(Target::get().writeMemory(m_trampoline, a.m_buffer.data(), a.m_buffer.size()));

	return Ok();
}

Result<> X64HandlerGenerator::relocateBranchInstruction(cs_insn* insn, uint8_t* buffer, uint64_t& trampolineAddress, uint64_t& originalAddress, int64_t targetAddress) {
	auto const id = insn->id;
	auto const detail = insn->detail;
	auto const address = insn->address;
	auto const size = insn->size;
	auto const difference = static_cast<intptr_t>(trampolineAddress) - static_cast<intptr_t>(originalAddress);

	if (difference <= 0x7fffffffll && difference >= -0x80000000ll) {
		return X86HandlerGenerator::relocateBranchInstruction(insn, buffer, trampolineAddress, originalAddress, targetAddress);
	}

	if (id == X86_INS_JMP) {
		X64Assembler a(trampolineAddress);
		RegMem64 m;
		using enum X64Register;

		a.jmpip("absolute-pointer");
		a.label("absolute-pointer");
		a.write64(targetAddress);

		a.updateLabels();

		auto bytes = std::move(a.m_buffer);
		std::memcpy(buffer, bytes.data(), bytes.size());

		trampolineAddress += bytes.size();
		originalAddress += size;
	}
	else if (id == X86_INS_CALL) {
		X64Assembler a(trampolineAddress);
		RegMem64 m;
		using enum X64Register;

		a.callip("absolute-pointer");
		a.jmp("skip-pointer");

		a.label("absolute-pointer");
		a.write64(targetAddress);

		a.label("skip-pointer");

		a.updateLabels();

		auto bytes = std::move(a.m_buffer);
		std::memcpy(buffer, bytes.data(), bytes.size());

		trampolineAddress += bytes.size();
		originalAddress += size;
	}
	else {
		X64Assembler a(trampolineAddress);
		RegMem64 m;
		using enum X64Register;

		// conditional branch
		a.write8(0x0f);
		if (size == 2) {
			a.write8(insn->bytes[0] + 0x10);
		}
		else {
			a.write8(insn->bytes[1]);
		}
		a.label32("jmp-on-branch");

		a.jmp("skip-branch");

		a.label("jmp-on-branch");

		a.jmpip("absolute-pointer");
		a.label("absolute-pointer");
		a.write64(targetAddress);
		
		a.label("skip-branch");

		a.updateLabels();

		auto bytes = std::move(a.m_buffer);
		std::memcpy(buffer, bytes.data(), bytes.size());

		trampolineAddress += bytes.size();
		originalAddress += size;
	}
	return Ok();
}