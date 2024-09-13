#include "X64Generator.hpp"

#include "../Handler.hpp"
#include "../assembler/X64Assembler.hpp"
#include "../target/PlatformTarget.hpp"

#include <CallingConvention.hpp>
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
	constexpr auto PRESERVE_SIZE = 0x80;
	// a.sub(RSP, PRESERVE_SIZE);

	a.mov(m[RSP + 0x78], R9);
	a.mov(m[RSP + 0x70], R8);
	a.mov(m[RSP + 0x68], RDX);
	a.mov(m[RSP + 0x60], RCX);
	a.movaps(m[RSP + 0x50], XMM3);
	a.movaps(m[RSP + 0x40], XMM2);
	a.movaps(m[RSP + 0x30], XMM1);
	a.movaps(m[RSP + 0x20], XMM0);
#else
	constexpr auto PRESERVE_SIZE = 0xc0;
	// a.sub(RSP, PRESERVE_SIZE);

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
	a.movaps(XMM0, m[RSP + 0x20]);
	a.movaps(XMM1, m[RSP + 0x30]);
	a.movaps(XMM2, m[RSP + 0x40]);
	a.movaps(XMM3, m[RSP + 0x50]);
	a.mov(RCX, m[RSP + 0x60]);
	a.mov(RDX, m[RSP + 0x68]);
	a.mov(R8, m[RSP + 0x70]);
	a.mov(R9, m[RSP + 0x78]);

	// a.add(RSP, size);
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

	// a.add(RSP, size);
#endif
}

size_t X64HandlerGenerator::preserveReturnRegisters(X64Assembler& a) {
	using enum X64Register;
	RegMem64 m;
#ifdef TULIP_HOOK_WINDOWS
	constexpr auto PRESERVE_SIZE = 0x40;
	// a.sub(RSP, PRESERVE_SIZE);

	a.movaps(m[RSP + 0x20], XMM0);
	a.mov(RSP + 0x30, RAX);
#else
	constexpr auto PRESERVE_SIZE = 0x40;
	// a.sub(RSP, PRESERVE_SIZE);

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
	a.mov(RAX, m[RSP + 0x30]);
	a.movaps(XMM0, m[RSP + 0x20]);

	// a.add(RSP, size);
#else
	a.mov(RDX, m[RSP + 0x28]);
	a.mov(RAX, m[RSP + 0x20]);
	a.movaps(XMM1, m[RSP + 0x10]);
	a.movaps(XMM0, m[RSP + 0x00]);

	// a.add(RSP, size);
#endif
}

#ifdef TULIP_HOOK_WINDOWS
namespace {
    size_t getStackParamSize(AbstractFunction const& function) {
        size_t stackParamSize = 0;
        int regCount = 0;
        if (function.m_return.m_kind == AbstractTypeKind::Other) {
            regCount += 1;
        }
        for (auto& param : function.m_parameters) {
            if (regCount < 4) {
                regCount++;
            } else {
                stackParamSize += 8;
            }
        }
        return stackParamSize;
    }
    size_t getPaddedStackParamSize(AbstractFunction const& function) {
        auto stackParamSize = getStackParamSize(function);
        return (stackParamSize % 16) ? stackParamSize + 8 : stackParamSize;
    }
}
#endif

Result<FunctionData> X64HandlerGenerator::generateHandler() {
	auto address = reinterpret_cast<uint64_t>(m_handler);
	X64Assembler a(address);
	RegMem64 m;
	using enum X64Register;

#ifdef TULIP_HOOK_WINDOWS
	constexpr auto FIRST_PARAM = RCX;
#else
	constexpr auto FIRST_PARAM = RDI;
#endif

	// for (size_t i = 0; i < 8; ++i) {
	// 	a.nop();
	// }

	a.push(RBP);
	a.label("handler-push");
	a.mov(RBP, RSP);
	// shadow space
	a.sub(RSP, 0xc0);
	a.label("handler-alloc-mid");
	// preserve registers
	const auto preservedSize = preserveRegisters(a);

	// set the parameters
	a.mov(FIRST_PARAM, "content");

	// call the pre handler, incrementing
	a.callip("handlerPre");

	// store rax (next function ptr) in the shadow space for a bit
	a.mov(m[RBP - 0x10], RAX);

	// recover registers
	restoreRegisters(a, preservedSize);

	// convert the current cc into the default cc
	m_metadata.m_convention->generateIntoDefault(a, m_metadata.m_abstract);

	// restore the next function ptr from shadow space
	a.mov(RAX, m[RBP - 0x10]);

	// call the func
	// a.int3();
	a.call(RAX);
	// // a.int3();
	m_metadata.m_convention->generateDefaultCleanup(a, m_metadata.m_abstract);

	// preserve the return values
	const auto returnPreservedSize = preserveReturnRegisters(a);

	// call the post handler, decrementing
	a.callip("handlerPost");

	// recover the return values
	restoreReturnRegisters(a, returnPreservedSize);

	// done!
	a.add(RSP, 0xc0);
	a.pop(RBP);
	a.ret();

	a.label("handlerPre");
	a.write64(reinterpret_cast<uint64_t>(preHandler));

	a.label("handlerPost");
	a.write64(reinterpret_cast<uint64_t>(postHandler));

	a.label("content");
	a.write64(reinterpret_cast<uint64_t>(m_content));

	a.updateLabels();

	a.align16();

	auto codeSize = a.m_buffer.size();

	#ifdef TULIP_HOOK_WINDOWS

	// UNWIND_INFO structure & RUNTIME_FUNCTION structure

	{
		auto const offsetBegin = address & 0xffff;
		auto const offsetEnd = (address + a.m_buffer.size()) & 0xffff;

		auto const pushOffset = reinterpret_cast<uint64_t>(a.getLabel("handler-push")) & 0xffff;
		auto const allocOffset = reinterpret_cast<uint64_t>(a.getLabel("handler-alloc-mid")) & 0xffff;
		// auto const conventionOffset = reinterpret_cast<uint64_t>(a.getLabel("convention-alloc-small")) & 0xffff;
		auto const prologSize = allocOffset;


		// RUNTIME_FUNCTION

		a.write32(offsetBegin); // BeginAddress
		a.write32(offsetEnd); // EndAddress
		a.write32(offsetEnd + 0xc); // UnwindData

		// UNWIND_INFO

		a.write8(
			0x1 | // Version : 3
			0x0 // Flags : 5
		);
		a.write8(prologSize); // SizeOfProlog
		a.write8(3); // CountOfUnwindCodes
		a.write8(
			0x0 | // FrameRegister : 4
			0x0  // FrameOffset : 4
		);
		// UNWIND_CODE[]

		// auto padded = 0x20 + getPaddedStackParamSize(m_metadata.m_abstract);
		// a.write8(conventionOffset); // CodeOffset
		// a.write8(
		// 	(((padded >> 3) - 1) << 4) | // UnwindOp : 4
		// 	0x2  // OpInfo : 4
		// );

		a.write8(allocOffset); // CodeOffset
		a.write8(
			0x0 | // UnwindOp : 4
			0x1  // OpInfo : 4
		);
		a.write16(0xc0 >> 3); // UWOP_ALLOC_LARGE continuation

		a.write8(pushOffset); // CodeOffset
		a.write8(
			0x50 | // UnwindOp : 4
			0x0  // OpInfo : 4
		);
	}

	#endif

	TULIP_HOOK_UNWRAP(Target::get().writeMemory(m_handler, a.m_buffer.data(), a.m_buffer.size()));

	return Ok(FunctionData{m_handler, codeSize});
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

	auto setReg = [&](auto set, auto& reg) {
		switch (set) {
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
			default: break;
		};
	};

	auto& operand0 = detail->x86.operands[0];
	auto& operand1 = detail->x86.operands[1];

	if (id == X86_INS_MOV && operand1.type == X86_OP_MEM) {
		X64Register reg;
		setReg(operand0.reg, reg);

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
	else if (id == X86_INS_LEA && operand1.type == X86_OP_MEM) {
		X64Register reg;
		setReg(operand0.reg, reg);

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
	else if (id == X86_INS_CMP && (operand0.type == X86_OP_MEM || operand1.type == X86_OP_MEM)) {
		X64Assembler a(trampolineAddress);
		RegMem64 m;
		using enum X64Register;

		auto const absolute = static_cast<intptr_t>(originalAddress) + size + disp;

		a.mov(RAX, "absolute-pointer");
		a.mov(RAX, m[RAX]);
		if (operand1.type == X86_OP_REG) {
			X64Register reg;
			setReg(operand1.reg, reg);
			a.cmp(RAX, reg);
		}
		else if (operand1.type == X86_OP_IMM) {
			a.cmp(RAX, operand1.imm);
		}
		else if (operand0.type == X86_OP_REG) {
			X64Register reg;
			setReg(operand0.reg, reg);
			a.cmp(reg, RAX);
		}
		else {
			return Err("Unknown operand when relocating cmp instruction");
		}
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
	else if (id == X86_INS_JMP && operand0.type == X86_OP_MEM) {
		X64Assembler a(trampolineAddress);
		RegMem64 m;
		using enum X64Register;

		auto const absolute = static_cast<intptr_t>(originalAddress) + size + disp;

		a.jmpip("absolute-pointer");

		a.label("absolute-pointer");
		// it's bad but umm better than the alternative of double indirection
		a.write64(*reinterpret_cast<uint64_t*>(absolute));

		a.updateLabels();

		auto bytes = std::move(a.m_buffer);
		std::memcpy(buffer, bytes.data(), bytes.size());

		trampolineAddress += bytes.size();
		originalAddress += size;
		return Ok();
	}
	else if (id == X86_INS_CALL && operand0.type == X86_OP_MEM) {
		X64Assembler a(trampolineAddress);
		RegMem64 m;
		using enum X64Register;

		auto const absolute = static_cast<intptr_t>(originalAddress) + size + disp;

		a.callip("absolute-pointer");
		a.jmp("skip-pointer");

		a.label("absolute-pointer");
		// it's bad but umm better than the alternative of double indirection
		a.write64(*reinterpret_cast<uint64_t*>(absolute));

		a.label("skip-pointer");

		a.updateLabels();

		auto bytes = std::move(a.m_buffer);
		std::memcpy(buffer, bytes.data(), bytes.size());

		trampolineAddress += bytes.size();
		originalAddress += size;
		return Ok();
	}
	else if (detail->x86.encoding.modrm_offset > 0 && (detail->x86.modrm | 0b11000111 == 5)) {
		// Trying to catch XMM instructions
		X64Assembler a(trampolineAddress);
		RegMem64 m;
		using enum X64Register;

		auto const absolute = static_cast<intptr_t>(originalAddress) + size + disp;

		a.mov(RAX, "absolute-pointer");
		a.mov(RAX, m[RAX]);
		for (size_t i = 0; i < size; ++i) {
			if (i == detail->x86.encoding.modrm_offset) {
				// remove the modrm displacement to make it rax
				a.write8(insn->bytes[i] & 0b00111000);
			}
			else {
				a.write8(insn->bytes[i]);
			}
		}
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
	a.label("wrapper-push");
	a.mov(RBP, RSP);

	// shadow space
	a.sub(RSP, 0xc0);
	a.label("wrapper-alloc-mid");

	m_metadata.m_convention->generateIntoOriginal(a, m_metadata.m_abstract);

	auto difference = a.currentAddress() - reinterpret_cast<int64_t>(m_address) + 5;
	if (difference <= 0x7fffffffll && difference >= -0x80000000ll) {
		a.call(reinterpret_cast<uint64_t>(m_address));
	}
	else {
		a.callip("address");
	}

	m_metadata.m_convention->generateOriginalCleanup(a, m_metadata.m_abstract);

	a.add(RSP, 0xc0);

	a.pop(RBP);
	a.ret();

	a.label("address");
	a.write64(reinterpret_cast<uintptr_t>(m_address));

	a.updateLabels();

	a.align16();

	return std::move(a.m_buffer);
}

#ifdef TULIP_HOOK_WINDOWS
std::vector<uint8_t> X64WrapperGenerator::unwindInfoBytes(uint64_t address) {
	X64Assembler a(address);

	{
		auto const offsetBegin = address & 0xffff;
		auto const offsetEnd = (address + a.m_buffer.size()) & 0xffff;

		auto const pushOffset = reinterpret_cast<uint64_t>(a.getLabel("wrapper-push")) & 0xffff;
		auto const allocOffset = reinterpret_cast<uint64_t>(a.getLabel("wrapper-alloc-mid")) & 0xffff;
		// auto const conventionOffset = reinterpret_cast<uint64_t>(a.getLabel("convention-alloc-small")) & 0xffff;
		auto const prologSize = allocOffset;


		// RUNTIME_FUNCTION

		a.label("wrapper-unwind-info");

		a.write32(offsetBegin); // BeginAddress
		a.write32(offsetEnd); // EndAddress
		a.write32(offsetEnd + 0xc); // UnwindData

		// UNWIND_INFO

		a.write8(
			0x1 | // Version : 3
			0x0 // Flags : 5
		);
		a.write8(prologSize); // SizeOfProlog
		a.write8(3); // CountOfUnwindCodes
		a.write8(
			0x0 | // FrameRegister : 4
			0x0  // FrameOffset : 4
		);
		// UNWIND_CODE[]

		a.write8(allocOffset); // CodeOffset
		a.write8(
			0x0 | // UnwindOp : 4
			0x1  // OpInfo : 4
		);
		a.write16(0xc0 >> 3); // UWOP_ALLOC_LARGE continuation

		a.write8(pushOffset); // CodeOffset
		a.write8(
			0x50 | // UnwindOp : 4
			0x0  // OpInfo : 4
		);
	}

	return std::move(a.m_buffer);
}
#endif

Result<FunctionData> X64WrapperGenerator::generateWrapper() {
	if (!m_metadata.m_convention->needsWrapper(m_metadata.m_abstract)) {
		return Ok(FunctionData{m_address, 0});
	}

	// this is silly, butt
	auto codeSize = this->wrapperBytes(0).size();

#ifdef TULIP_HOOK_WINDOWS
	auto unwindInfoSize = this->unwindInfoBytes(0).size();
	auto totalSize = codeSize + unwindInfoSize;
#else
	auto totalSize = codeSize;
#endif

	auto areaSize = (totalSize + (0x20 - totalSize) % 0x20);

	TULIP_HOOK_UNWRAP_INTO(auto area, Target::get().allocateArea(areaSize));
	auto address = reinterpret_cast<uint64_t>(area);

	auto code = this->wrapperBytes(address);
	codeSize = code.size();

#ifdef TULIP_HOOK_WINDOWS
	auto unwindInfo = this->unwindInfoBytes(address + codeSize);
	code.insert(code.end(), unwindInfo.begin(), unwindInfo.end());
#endif

	TULIP_HOOK_UNWRAP(Target::get().writeMemory(area, code.data(), code.size()));

	return Ok(FunctionData{area, codeSize});
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

Result<FunctionData> X64HandlerGenerator::generateTrampoline(uint64_t target) {
	X64Assembler a(reinterpret_cast<uint64_t>(m_trampoline));
	using enum X64Register;

	if (m_metadata.m_convention->needsWrapper(m_metadata.m_abstract)) {
		a.push(RBP);
		a.label("trampoline-push");
		a.mov(RBP, RSP);

		// shadow space
		a.sub(RSP, 0xc0);
		a.label("trampoline-alloc-mid");

		m_metadata.m_convention->generateIntoOriginal(a, m_metadata.m_abstract);

		a.call("relocated");

		m_metadata.m_convention->generateOriginalCleanup(a, m_metadata.m_abstract);

		a.add(RSP, 0xc0);

		a.pop(RBP);
		a.ret();
	}

	auto codeSizeFake = a.m_buffer.size();

	a.label("relocated");

	TULIP_HOOK_UNWRAP_INTO(auto code, this->relocatedBytes(a.currentAddress(), target));

	a.m_buffer.insert(a.m_buffer.end(), code.m_relocatedBytes.begin(), code.m_relocatedBytes.end());

	auto difference = a.currentAddress() - reinterpret_cast<int64_t>(m_address) + 5 - code.m_originalOffset;

	if (difference <= 0x7fffffffll && difference >= -0x80000000ll) {
		a.jmp(reinterpret_cast<uint64_t>(m_address) + code.m_originalOffset);
	}
	else {
		a.jmpip("handler");

		a.label("handler");
		a.write64(reinterpret_cast<uint64_t>(m_address) + code.m_originalOffset);
	}

	a.updateLabels();

	a.align16();


#ifdef TULIP_HOOK_WINDOWS

	if (m_metadata.m_convention->needsWrapper(m_metadata.m_abstract)) {
		auto const address = reinterpret_cast<uint64_t>(m_trampoline);
		auto const offsetBegin = address & 0xffff;
		auto const offsetEnd = (address + a.m_buffer.size()) & 0xffff;

		auto const pushOffset = reinterpret_cast<uint64_t>(a.getLabel("trampoline-push")) & 0xffff;
		auto const allocOffset = reinterpret_cast<uint64_t>(a.getLabel("trampoline-alloc-mid")) & 0xffff;
		// auto const conventionOffset = reinterpret_cast<uint64_t>(a.getLabel("convention-alloc-small")) & 0xffff;
		auto const prologSize = allocOffset;


		// RUNTIME_FUNCTION

		a.write32(offsetBegin); // BeginAddress
		a.write32(offsetEnd); // EndAddress
		a.write32(offsetEnd + 0xc); // UnwindData

		// UNWIND_INFO

		a.write8(
			0x1 | // Version : 3
			0x0 // Flags : 5
		);
		a.write8(prologSize); // SizeOfProlog
		a.write8(3); // CountOfUnwindCodes
		a.write8(
			0x0 | // FrameRegister : 4
			0x0  // FrameOffset : 4
		);
		// UNWIND_CODE[]

		a.write8(allocOffset); // CodeOffset
		a.write8(
			0x0 | // UnwindOp : 4
			0x1  // OpInfo : 4
		);
		a.write16(0xc0 >> 3); // UWOP_ALLOC_LARGE continuation

		a.write8(pushOffset); // CodeOffset
		a.write8(
			0x50 | // UnwindOp : 4
			0x0  // OpInfo : 4
		);
	}

#endif

	// auto codeSize = a.m_buffer.size();
	// auto areaSize = (codeSize + (0x20 - codeSize) % 0x20);

	TULIP_HOOK_UNWRAP(Target::get().writeMemory(m_trampoline, a.m_buffer.data(), a.m_buffer.size()));

	return Ok(FunctionData{m_trampoline, codeSizeFake});
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
	else if (targetAddress - reinterpret_cast<int64_t>(m_address) < m_modifiedBytesSize) {
		// conditional branch that jmps to code we relocated, so we need to keep track of where it jumps to
		// relocation is later done in X86HandlerGenerator::relocatedBytes
		std::memcpy(buffer, insn->bytes, size);
		if (size == 2) {
			auto* relativeByte = reinterpret_cast<int8_t*>(buffer + 1);
			*relativeByte = -1;
			m_shortBranchRelocations[targetAddress] = relativeByte;
		} else {
			// what
			std::cerr << "Unhandled short branch relocation of " << insn->mnemonic << " with size=" << size << std::endl;
		}

		trampolineAddress += size;
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