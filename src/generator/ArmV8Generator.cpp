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

namespace {
	bool canDeltaRange(int64_t delta, int64_t range) {
		// Check if the delta can be encoded in range bits or less.
		return delta >= -(1ll << range) && delta <= (1ll << range) - 1;
	}
}

std::vector<uint8_t> ArmV8HandlerGenerator::intervenerBytes(uint64_t address, size_t size) {
    ArmV8Assembler a(address);
    using enum ArmV8Register;

	const auto callback = reinterpret_cast<int64_t>(m_handler);
	const int64_t alignedAddr = address & ~0xFFF;
	const int64_t alignedCallback = callback & ~0xFFF;
	const int64_t delta = callback - static_cast<int64_t>(address);

	// Delta can be encoded in 28 bits or less -> use branch.
	if (canDeltaRange(delta, 28)) {
		a.b(delta);
	}
	// Delta can be encoded in 33 bits or less -> use adrp.
	else if (canDeltaRange(delta, 33)) {
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

	size_t idx = 0;

	while (d.hasNext()) {
		using enum ArmV8InstructionType;
		auto baseIns = d.disassembleNext();
		auto ins = static_cast<ArmV8Instruction*>(baseIns.get());

		auto idxLabel = std::to_string(idx);

		auto const newOffset = ins->m_literal - a.currentAddress();
		auto const callback = ins->m_literal;
		auto const alignedAddr = a.currentAddress() & ~0xFFFll;
		auto const alignedCallback = callback & ~0xFFFll;

		switch (ins->m_type) {
			case ArmV8InstructionType::B: {
				if (canDeltaRange(newOffset, 28)) {
					a.b(newOffset);
				} else if (canDeltaRange(newOffset, 33)) {
					a.adrp(X16, alignedCallback - alignedAddr);
					a.add(X16, X16, callback & 0xFFF);
					a.br(X16);
				} else {
					a.ldr(X16, "literal-" + idxLabel);
					a.br(X16);

					a.label("literal-" + idxLabel);
					a.write64(ins->m_literal);
				}
				break;
			}
			case ArmV8InstructionType::BL: {
				if (canDeltaRange(newOffset, 28)) {
					a.bl(newOffset);
				} else if (canDeltaRange(newOffset, 33)) {
					a.adrp(X16, alignedCallback - alignedAddr);
					a.add(X16, X16, callback & 0xFFF);
					a.blr(X16);
				} else {
					a.ldr(X16, "literal-" + idxLabel);
					a.blr(X16);
					a.b("jump-" + idxLabel);

					a.label("literal-" + idxLabel);
					a.write64(ins->m_literal);

					a.label("jump-" + idxLabel);
				}
				break;
			}
			case ArmV8InstructionType::LDR_Literal: {
				if (canDeltaRange(newOffset, 21)) {
					a.ldr(ins->m_dst1, newOffset);
				} else if (canDeltaRange(newOffset, 33)) {
					a.adrp(X16, alignedCallback - alignedAddr);
					a.add(X16, X16, callback & 0xFFF);
					a.ldr(ins->m_dst1, X16, 0);
				} else {
					a.ldr(X16, "literal-" + idxLabel);
					a.ldr(ins->m_dst1, X16, 0);
					a.b("jump-" + idxLabel);

					a.label("literal-" + idxLabel);
					a.write64(ins->m_literal);

					a.label("jump-" + idxLabel);
				} 
				break;
			}
			case ArmV8InstructionType::ADR: {
				if (canDeltaRange(newOffset, 21)) {
					a.adr(ins->m_dst1, newOffset);
				} else if (canDeltaRange(newOffset, 33)) {
					a.adrp(X16, alignedCallback - alignedAddr);
					a.add(X16, X16, callback & 0xFFF);
				} else {
					a.ldr(ins->m_dst1, "literal-" + idxLabel);
					a.b("jump-" + idxLabel);

					a.label("literal-" + idxLabel);
					a.write64(ins->m_literal);

					a.label("jump-" + idxLabel);
				}
				break;
			}
			case ArmV8InstructionType::ADRP: {
				if (canDeltaRange(newOffset, 33)) {
					a.adrp(ins->m_dst1, alignedCallback - alignedAddr);
				} else {
					a.ldr(ins->m_dst1, "literal-" + idxLabel);
					a.b("jump-" + idxLabel);

					a.label("literal-" + idxLabel);
					a.write64(ins->m_literal);

					a.label("jump-" + idxLabel);
				}
				break;
			}
			case ArmV8InstructionType::B_Cond: {
				if (canDeltaRange(newOffset, 33)) {
					a.adrp(X16, alignedCallback - alignedAddr);
					a.add(X16, X16, callback & 0xFFF);
					a.write32(
						(ins->m_rawInstruction & 0xFF00001F) | // Preserve the condition bits
						(2 << 5)
					);
					a.b("jump-" + idxLabel);
					a.br(X16);

					a.label("jump-" + idxLabel);
				}
				else {
					a.ldr(X16, "literal-" + idxLabel);
					a.write32(
						(ins->m_rawInstruction & 0xFF00001F) | // Preserve the condition bits
						(2 << 5)
					);
					a.b("jump-" + idxLabel);
					a.br(X16);

					a.label("literal-" + idxLabel);
					a.write64(ins->m_literal);

					a.label("jump-" + idxLabel);
				}
				break;
			}
			case ArmV8InstructionType::CB_: {
				if (canDeltaRange(newOffset, 33)) {
					a.adrp(X16, alignedCallback - alignedAddr);
					a.add(X16, X16, callback & 0xFFF);
					a.write32(
						(ins->m_rawInstruction & 0xFFFFE01F) | // Preserve the real bits
						(2 << 5)
					);
					a.b("jump-" + idxLabel);
					a.br(X16);

					a.label("jump-" + idxLabel);
				} else {
					a.ldr(X16, "literal-" + idxLabel);
					a.write32(
						(ins->m_rawInstruction & 0xFFFFE01F) | // Preserve the real bits
						(2 << 5)
					);
					a.b("jump-" + idxLabel);
					a.br(X16);

					a.label("literal-" + idxLabel);
					a.write64(ins->m_literal);

					a.label("jump-" + idxLabel);
				}
				break;
			}
			case ArmV8InstructionType::TBZ: {
				if (canDeltaRange(newOffset, 33)) {
					a.adrp(X16, alignedCallback - alignedAddr);
					a.add(X16, X16, callback & 0xFFF);
					a.tbz(ins->m_src1, ins->m_other, 8);

					a.b("jump-" + idxLabel);
					a.br(X16);

					a.label("jump-" + idxLabel);
				} else {
					a.ldr(X16, "literal-" + idxLabel);
					a.tbz(ins->m_src1, ins->m_other, 8);

					a.b("jump-" + idxLabel);
					a.br(X16);

					a.label("literal-" + idxLabel);
					a.write64(ins->m_literal);

					a.label("jump-" + idxLabel);
				}
				break;
			}
			case ArmV8InstructionType::TBNZ: {
				if (canDeltaRange(newOffset, 33)) {
					a.adrp(X16, alignedCallback - alignedAddr);
					a.add(X16, X16, callback & 0xFFF);
					a.tbnz(ins->m_src1, ins->m_other, 8);
					a.b("jump-" + idxLabel);
					a.br(X16);

					a.label("jump-" + idxLabel);
				} else {
					a.ldr(X16, "literal-" + idxLabel);
					a.tbnz(ins->m_src1, ins->m_other, 8);
					a.b("jump-" + idxLabel);
					a.br(X16);

					a.label("literal-" + idxLabel);
					a.write64(ins->m_literal);

					a.label("jump-" + idxLabel);
				}
				break;
			}
			default:
				a.write32(ins->m_rawInstruction);
				break;
		}

		idx++;
	}

	auto const newOffset = (address + target) - a.currentAddress();
	if (canDeltaRange(newOffset, 28)) {
		a.b(newOffset);
	} else if (canDeltaRange(newOffset, 33)) {
		auto const callback = address + target;
		auto const alignedCallback = callback & ~0xFFFll;
		auto const alignedAddress = a.currentAddress() & ~0xFFFll;
		a.adrp(X16, alignedCallback - alignedAddress);
		a.add(X16, X16, callback & 0xFFF);
		a.br(X16);
	} else {
		a.ldr(X16, "literal-final");
		a.br(X16);

		a.label("literal-final");
		a.write64(address + target);
	}

	a.updateLabels();

	GEODE_UNWRAP(Target::get().writeMemory(m_trampoline, a.m_buffer.data(), a.m_buffer.size()));

	return geode::Ok(TrampolineReturn{FunctionData{m_trampoline, a.m_buffer.size()}, a.m_buffer.size()});
}
