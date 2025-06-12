#include "ArmV8Generator.hpp"

#include "../Handler.hpp"
#include "../assembler/ArmV8Assembler.hpp"
#include "../target/PlatformTarget.hpp"

#include <InstructionRelocation/InstructionRelocation.h>

using namespace tulip::hook;

HandlerGenerator::HandlerReturn PatchlessArmV8HandlerGenerator::handlerBytes(uint64_t address) {
    ArmV8Assembler a(address);
    using enum ArmV8Register;

	a.adr(X14, 0);

    a.stp(X29, X30, SP, -0xc0, ArmV8IndexKind::PreIndex);
    a.mov(X29, SP);
    a.stp(X19, X20, SP, 0x10, ArmV8IndexKind::SignedOffset);
    
    a.mov(X19, X30);
    a.mov(X20, X14);

    a.stp(X0, X1, SP, 0x20, ArmV8IndexKind::SignedOffset);
    a.stp(X2, X3, SP, 0x30, ArmV8IndexKind::SignedOffset);
    a.stp(X4, X5, SP, 0x40, ArmV8IndexKind::SignedOffset);
    a.stp(X6, X7, SP, 0x50, ArmV8IndexKind::SignedOffset);
    a.stp(X8, X9, SP, 0x60, ArmV8IndexKind::SignedOffset);
    a.stp(D0, D1, SP, 0x70, ArmV8IndexKind::SignedOffset);
    a.stp(D2, D3, SP, 0x80, ArmV8IndexKind::SignedOffset);
    a.stp(D4, D5, SP, 0x90, ArmV8IndexKind::SignedOffset);
    a.stp(D6, D7, SP, 0xa0, ArmV8IndexKind::SignedOffset);

    // set the parameters
    a.mov(X0, X16);
    a.mov(X1, X17);
    a.mov(X2, X15);
    a.mov(X3, X14);
    a.mov(X4, 0);

    // call the func
    a.ldr(X5, "commonHandlerStorage");
    a.add(X5, X5, X20);
    a.ldr(X5, X5);
    a.blr(X5);
    a.mov(X16, X0);

    // recover registers
    a.ldp(D6, D7, SP, 0xa0, ArmV8IndexKind::SignedOffset);
    a.ldp(D4, D5, SP, 0x90, ArmV8IndexKind::SignedOffset);
    a.ldp(D2, D3, SP, 0x80, ArmV8IndexKind::SignedOffset);
    a.ldp(D0, D1, SP, 0x70, ArmV8IndexKind::SignedOffset);
    a.ldp(X8, X9, SP, 0x60, ArmV8IndexKind::SignedOffset);
    a.ldp(X6, X7, SP, 0x50, ArmV8IndexKind::SignedOffset);
    a.ldp(X4, X5, SP, 0x40, ArmV8IndexKind::SignedOffset);
    a.ldp(X2, X3, SP, 0x30, ArmV8IndexKind::SignedOffset);
    a.ldp(X0, X1, SP, 0x20, ArmV8IndexKind::SignedOffset);

    a.blr(X16);

    a.stp(X0, X8, SP, 0x20, ArmV8IndexKind::SignedOffset);
    a.stp(D0, D1, SP, 0x30, ArmV8IndexKind::SignedOffset);

    // call the post handler, decrementing
    a.mov(X4, 1);
    a.ldr(X5, "commonHandlerStorage");
    a.add(X5, X5, X20);
    a.ldr(X5, X5);
    a.blr(X5);

    // recover the original return
    a.mov(X16, X19);

    // recover the return values
    a.ldp(D0, D1, SP, 0x30, ArmV8IndexKind::SignedOffset);
    a.ldp(X0, X8, SP, 0x20, ArmV8IndexKind::SignedOffset);

    a.ldp(X19, X20, SP, 0x10, ArmV8IndexKind::SignedOffset);
    a.ldp(X29, X30, SP, 0xc0, ArmV8IndexKind::PostIndex);

    // done!
    a.br(X16);

    a.label("commonHandlerStorage");
    a.write64(reinterpret_cast<uint64_t>(m_content));

    a.updateLabels();

	auto codeSize = a.m_buffer.size();

	return HandlerReturn{
		.m_handlerBytes = std::move(a.m_buffer),
		.m_codeSize = codeSize
	};
}
