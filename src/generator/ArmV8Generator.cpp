#include "ArmV8Generator.hpp"

#include "../Handler.hpp"
#include "../assembler/ArmV8Assembler.hpp"
#include "../disassembler/ArmV8Disassembler.hpp"
#include "../target/PlatformTarget.hpp"

using namespace tulip::hook;

namespace {
	void* TULIP_HOOK_DEFAULT_CONV preHandler(HandlerContent* content) {
		Handler::incrementIndex(content);
		auto ret = Handler::getNextFunction(content);
		return ret;
	}

	void TULIP_HOOK_DEFAULT_CONV postHandler() {
		Handler::decrementIndex();
		return;
	}
}

std::vector<uint8_t> ArmV8HandlerGenerator::handlerBytes(uint64_t address) {
    ArmV8Assembler a(address);
    using enum ArmV8Register;
	using enum ArmV8IndexKind;

    // preserve registers
	a.stp(X29, X30, SP, -0xc0, PreIndex);
    a.mov(X29, SP);

    a.stp(X0, X1, SP, 0x10, SignedOffset);
    a.stp(X2, X3, SP, 0x20, SignedOffset);
    a.stp(X4, X5, SP, 0x30, SignedOffset);
    a.stp(X6, X7, SP, 0x40, SignedOffset);
    a.stp(X8, X9, SP, 0x50, SignedOffset);
    a.stp(D0, D1, SP, 0x60, SignedOffset);
    a.stp(D2, D3, SP, 0x70, SignedOffset);
    a.stp(D4, D5, SP, 0x80, SignedOffset);
    a.stp(D6, D7, SP, 0x90, SignedOffset);

	// set the parameters
	a.ldr(X0, "content");

	// call the pre handler, incrementing
	a.ldr(X1, "handlerPre");
	a.blr(X1);
	a.mov(X16, X0);

	// recover registers
	a.ldp(D6, D7, SP, 0x90, SignedOffset);
	a.ldp(D4, D5, SP, 0x80, SignedOffset);
	a.ldp(D2, D3, SP, 0x70, SignedOffset);
	a.ldp(D0, D1, SP, 0x60, SignedOffset);
	a.ldp(X8, X9, SP, 0x50, SignedOffset);
	a.ldp(X6, X7, SP, 0x40, SignedOffset);
	a.ldp(X4, X5, SP, 0x30, SignedOffset);
	a.ldp(X2, X3, SP, 0x20, SignedOffset);
	a.ldp(X0, X1, SP, 0x10, SignedOffset);

	// call the func
	a.blr(X16);

	// preserve the return values
	a.stp(X0, X8, SP, 0x10, SignedOffset);
	a.stp(D0, D1, SP, 0x20, SignedOffset);

	// call the post handler, decrementing
	a.ldr(X0, "handlerPost");
	a.blr(X0);

	// recover the return values
	a.ldp(D0, D1, SP, 0x20, SignedOffset);
	a.ldp(X0, X8, SP, 0x10, SignedOffset);

	// done!
	a.ldp(X29, X30, SP, 0xc0, PostIndex);
	a.br(X30);

	// Align to 8 bytes for ldr.
	if (a.currentAddress() & 7)
		a.nop();

	a.label("handlerPre");
	a.write64(reinterpret_cast<uint64_t>(preHandler));

	a.label("handlerPost");
	a.write64(reinterpret_cast<uint64_t>(postHandler));

	a.label("content");
	a.write64(reinterpret_cast<uint64_t>(m_content));

	a.updateLabels();

	return std::move(a.m_buffer);
}

std::vector<uint8_t> ArmV8HandlerGenerator::intervenerBytes(uint64_t address, size_t size) {
    ArmV8Assembler a(address);
    using enum ArmV8Register;

	const auto callback = reinterpret_cast<int64_t>(m_handler);
	const int64_t alignedAddr = address & ~0xFFF;
	const int64_t alignedCallback = callback & ~0xFFF;
	const int64_t delta = callback - static_cast<int64_t>(address);

	// Delta can be encoded in 28 bits or less -> use branch.
	if (delta >= -0x8000000 && delta <= 0x7FFFFFF) {
		a.b(delta);
	}
	// Delta can be encoded in 33 bits or less -> use adrp.
	else if (delta >= -static_cast<int64_t>(0x100000000) && delta <= 0xFFFFFFFF) {
		a.adrp(X16, alignedCallback - alignedAddr);
		a.add(X16, X16, callback & 0xFFF);
		a.br(X16);
	}
	// Delta is too big -> use branch with register.
	else {
		// // Align to 8 bytes for ldr.
		// if (address & 7) {
		// 	a.nop();
		// }

		a.ldr(X16, "handler");
		a.br(X16);

		a.label("handler");
		a.write64(callback);
	}

	a.updateLabels();

    return std::move(a.m_buffer);
}

geode::Result<HandlerGenerator::TrampolineReturn> ArmV8HandlerGenerator::generateTrampoline(uint64_t target) {
	std::vector<uint8_t> originalBytes(target);
	std::memcpy(originalBytes.data(), m_address, target);

	auto address = reinterpret_cast<int64_t>(m_address);
	auto trampoline = reinterpret_cast<int64_t>(m_trampoline);

	ArmV8Disassembler d(address, originalBytes);
	ArmV8Assembler a(trampoline);
	using enum ArmV8Register;

	while (d.hasNext()) {
		using enum ArmV8InstructionType;
		auto ins = d.disassembleNext();
		
		switch (ins->m_type) {
			case ArmV8InstructionType::B: {
				auto const newOffset = ins->m_literal - a.currentAddress();
				if (newOffset < -0x8000000 || newOffset > 0x7FFFFFF) {
					a.adrp(X16, newOffset & ~0xFFFll);
					a.add(X16, X16, newOffset & 0xFFF);
					a.br(X16);
				} else {
					a.b(newOffset);
				}
				break;
			}
			case ArmV8InstructionType::BL: {
				auto const newOffset = ins->m_literal - a.currentAddress();
				if (newOffset < -0x2000000 || newOffset > 0x1FFFFFF) {
					a.adrp(X16, newOffset & ~0xFFFll);
					a.add(X16, X16, newOffset & 0xFFF);
					a.blr(X16);
				} else {
					a.bl(newOffset);
				}
				break;
			}
			case ArmV8InstructionType::LDR_Literal: {
				auto const newOffset = ins->m_literal - a.currentAddress();
				if (newOffset < -0x80000 || newOffset > 0x7FFFF) {
					a.adrp(X16, newOffset & ~0xFFFll);
					a.add(X16, X16, newOffset & 0xFFF);
					a.ldr(ins->m_dst1, X16, 0);
				} else {
					a.ldr(ins->m_dst1, newOffset);
				}
				break;
			}
			case ArmV8InstructionType::ADR: {
				auto const newOffset = ins->m_literal - a.currentAddress();
				a.adrp(ins->m_dst1, newOffset & ~0xFFFll);
				a.add(ins->m_dst1, ins->m_dst1, newOffset & 0xFFF);
			}
			case ArmV8InstructionType::ADRP: {
				auto const newOffset = ins->m_literal - a.currentAddress();
				a.adrp(ins->m_dst1, newOffset & ~0xFFFll);
			}
			case ArmV8InstructionType::B_Cond: {
				auto const newOffset = ins->m_literal - a.currentAddress();
				a.adrp(X16, newOffset & ~0xFFFll);
				a.add(X16, X16, newOffset & 0xFFF);
				a.write32(
					ins->m_rawInstruction & 0xFF00001F | // Preserve the condition bits
					(2 << 5)
				);
				a.b(8);
				a.br(X16);
				break;
			}
			case ArmV8InstructionType::TBZ:
				auto const newOffset = ins->m_literal - a.currentAddress();
				a.adrp(X16, newOffset & ~0xFFFll);
				a.add(X16, X16, newOffset & 0xFFF);
				a.tbz(ins->m_src1, ins->m_other, 8);
				a.b(8);
				a.br(X16);
				break;
			case ArmV8InstructionType::TBNZ:
				auto const newOffset = ins->m_literal - a.currentAddress();
				a.adrp(X16, newOffset & ~0xFFFll);
				a.add(X16, X16, newOffset & 0xFFF);
				a.tbnz(ins->m_src1, ins->m_other, 8);
				a.b(8);
				a.br(X16);
				break;
			default:
				a.write32(instruction->m_rawInstruction);
				break;
		}
	}

	auto const newOffset = a.currentAddress() - target;
	a.adrp(X16, target & ~0xFFFll);
	a.add(X16, X16, target & 0xFFF);
	a.br(X16);

	GEODE_UNWRAP(Target::get().writeMemory(m_trampoline, a.m_buffer.data(), a.m_buffer.size()));

	return geode::Ok(TrampolineReturn{FunctionData{m_trampoline, a.m_buffer.size()}, a.m_buffer.size()});
}
