#include "ArmV8Generator.hpp"

#include "../Handler.hpp"
#include "../assembler/ArmV8Assembler.hpp"
#include "../disassembler/ArmV8Disassembler.hpp"
#include "../target/PlatformTarget.hpp"
#include <tulip/CallingConvention.hpp>

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

std::vector<uint8_t> ArmV8Generator::handlerBytes(int64_t original, int64_t handler, void* content, HandlerMetadata const& metadata) {
	ArmV8Assembler a(handler);
    using enum ArmV8Register;
	using enum ArmV8IndexKind;

    // preserve registers
	a.stp(X29, X30, SP, -0x10, PreIndex);
    a.mov(X29, SP);
	a.sub(SP, SP, 0xb0);

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
	a.mov(X15, X0);

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

	// convert the current cc into the default cc
	metadata.m_convention->generateIntoDefault(a, metadata.m_abstract);

	// call the func
	a.blr(X15);

	metadata.m_convention->generateDefaultCleanup(a, metadata.m_abstract);

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
	a.add(SP, SP, 0xb0);
	a.ldp(X29, X30, SP, 0x10, PostIndex);
	a.br(X30);

	// Align to 8 bytes for ldr.
	if (a.currentAddress() & 7)
		a.nop();

	a.label("handlerPre");
	a.write64(reinterpret_cast<uint64_t>(preHandler));

	a.label("handlerPost");
	a.write64(reinterpret_cast<uint64_t>(postHandler));

	a.label("content");
	a.write64(reinterpret_cast<uint64_t>(content));

	a.updateLabels();

	return std::move(a.m_buffer);	
}
namespace {
	bool canDeltaRange(int64_t delta, int64_t range) {
		// Check if the delta can be encoded in range bits or less.
		return delta >= -(1ll << range) && delta <= (1ll << range) - 1;
	}
}

std::vector<uint8_t> ArmV8Generator::intervenerBytes(int64_t original, int64_t handler, size_t size) {
	ArmV8Assembler a(original);
    using enum ArmV8Register;

	const auto callback = handler;
	const int64_t alignedAddr = original & ~0xFFF;
	const int64_t alignedCallback = callback & ~0xFFF;
	const int64_t delta = callback - original;

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
geode::Result<BaseGenerator::RelocateReturn> ArmV8Generator::relocatedBytes(int64_t original, int64_t relocated, std::span<uint8_t const> originalBuffer) {
	auto address = original;
	auto trampoline = relocated;

	ArmV8Disassembler d(address, {originalBuffer.begin(), originalBuffer.end()});
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

	auto const newOffset = (address + originalBuffer.size()) - a.currentAddress();
	if (canDeltaRange(newOffset, 28)) {
		a.b(newOffset);
	} else if (canDeltaRange(newOffset, 33)) {
		auto const callback = address + originalBuffer.size();
		auto const alignedCallback = callback & ~0xFFFll;
		auto const alignedAddress = a.currentAddress() & ~0xFFFll;
		a.adrp(X16, alignedCallback - alignedAddress);
		a.add(X16, X16, callback & 0xFFF);
		a.br(X16);
	} else {
		a.ldr(X16, "literal-final");
		a.br(X16);

		a.label("literal-final");
		a.write64(address + originalBuffer.size());
	}

	a.updateLabels();

	return geode::Ok(RelocateReturn{std::move(a.m_buffer), originalBuffer.size()});
}

std::vector<uint8_t> ArmV8Generator::commonHandlerBytes(int64_t handler, ptrdiff_t spaceOffset) {
	ArmV8Assembler a(handler);
    using enum ArmV8Register;
	using enum ArmV8IndexKind;

	a.adr(X13, 0);

    a.stp(X29, X30, SP, -0xc0, PreIndex);
    a.mov(X29, SP);
    a.stp(X19, X20, SP, 0x10, SignedOffset);

    a.mov(X19, X30);
    a.mov(X20, X13);

    a.stp(X0, X1, SP, 0x20, SignedOffset);
    a.stp(X2, X3, SP, 0x30, SignedOffset);
    a.stp(X4, X5, SP, 0x40, SignedOffset);
    a.stp(X6, X7, SP, 0x50, SignedOffset);
    a.stp(X8, X9, SP, 0x60, SignedOffset);
    a.stp(D0, D1, SP, 0x70, SignedOffset);
    a.stp(D2, D3, SP, 0x80, SignedOffset);
    a.stp(D4, D5, SP, 0x90, SignedOffset);
    a.stp(D6, D7, SP, 0xa0, SignedOffset);

    // set the parameters
    a.mov(X0, X10);
    a.mov(X1, X11);
    a.mov(X2, X12);
    a.mov(X3, X13);
    a.mov(X4, 0);

    // call the func
    a.ldr(X5, "spaceOffset");
    a.add(X5, X5, X20);
    a.ldr(X5, X5, 0);
    a.blr(X5);
    a.mov(X16, X0);

    // recover registers
    a.ldp(D6, D7, SP, 0xa0, SignedOffset);
    a.ldp(D4, D5, SP, 0x90, SignedOffset);
    a.ldp(D2, D3, SP, 0x80, SignedOffset);
    a.ldp(D0, D1, SP, 0x70, SignedOffset);
    a.ldp(X8, X9, SP, 0x60, SignedOffset);
    a.ldp(X6, X7, SP, 0x50, SignedOffset);
    a.ldp(X4, X5, SP, 0x40, SignedOffset);
    a.ldp(X2, X3, SP, 0x30, SignedOffset);
    a.ldp(X0, X1, SP, 0x20, SignedOffset);

    a.blr(X16);

    a.stp(X0, X8, SP, 0x20, SignedOffset);
    a.stp(D0, D1, SP, 0x30, SignedOffset);

    // call the post handler, decrementing
    a.mov(X4, 1);
    a.ldr(X5, "spaceOffset");
    a.add(X5, X5, X20);
    a.ldr(X5, X5, 0);
    a.blr(X5);

    // recover the original return
    a.mov(X16, X19);

    // recover the return values
    a.ldp(D0, D1, SP, 0x30, SignedOffset);
    a.ldp(X0, X8, SP, 0x20, SignedOffset);

    a.ldp(X19, X20, SP, 0x10, SignedOffset);
    a.ldp(X29, X30, SP, 0xc0, PostIndex);

    // done!
    a.br(X16);

    a.label("spaceOffset");
    a.write64(spaceOffset);

    a.updateLabels();

	return std::move(a.m_buffer);
}
std::vector<uint8_t> ArmV8Generator::commonIntervenerBytes(int64_t original, int64_t handler, size_t unique, ptrdiff_t relocOffset) {
	ArmV8Assembler a(original);
    using enum ArmV8Register;

	a.adr(X10, 0);
	a.mov(X11, unique);
	a.mov(X12, relocOffset);

	const auto callback = handler;
	const int64_t alignedAddr = a.currentAddress() & ~0xFFF;
	const int64_t alignedCallback = callback & ~0xFFF;
	const int64_t delta = callback - a.currentAddress();

	if (canDeltaRange(delta, 28)) {
		a.b(delta);
	} else if (canDeltaRange(delta, 33)) {
		a.adrp(X16, alignedCallback - alignedAddr);
		a.add(X16, X16, callback & 0xFFF);
		a.br(X16);
	} else {
		a.ldr(X16, "handler");
		a.br(X16);

		a.label("handler");
		a.write64(callback);
	}

	a.updateLabels();

	return std::move(a.m_buffer);
}
