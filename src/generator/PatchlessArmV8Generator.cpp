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

    a.stp(X29, X30, SP, -16, PreIndex);
    a.mov(X29, SP);
    a.stp(X19, X20, SP, 16, SignedOffset);
    
    a.mov(X19, X30);
    a.mov(X20, X14);

    a.push({X0, X1, X2, X3, X4, X5, X6, X7, X8, X9});
    a.push({D0, D1, D2, D3, D4, D5, D6, D7});

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
    a.pop({D0, D1, D2, D3, D4, D5, D6, D7});
    a.pop({X0, X1, X2, X3, X4, X5, X6, X7, X8, X9});

    a.blr(X16);

    a.push({X0, X8});
    a.push({D0, D1});

    // call the post handler, decrementing
    a.mov(X4, 1);
    a.ldr(X5, "commonHandlerStorage");
    a.add(X5, X5, X20);
    a.ldr(X5, X5);
    a.blr(X5);

    // recover the original return
    a.mov(X16, X19);

    // recover the return values
    a.pop({D0, D1});
    a.pop({X0, X8});

    a.ldp(X19, X20, SP, 16, SignedOffset);
    a.ldp(X29, X30, SP, 32, PostIndex);

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
