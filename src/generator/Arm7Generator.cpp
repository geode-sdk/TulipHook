#include "Arm7Generator.hpp"

#include "../Handler.hpp"
#include "../assembler/Arm7Assembler.hpp"
#include "../target/PlatformTarget.hpp"

#include <CallingConvention.hpp>
#include <InstructionRelocation/InstructionRelocation.h>
#include <sstream>

using namespace tulip::hook;

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

Result<Arm7HandlerGenerator::RelocateReturn> Arm7HandlerGenerator::relocateOriginal(uint64_t target) {
	auto origin = new CodeMemBlock((uint64_t)m_address, target);
	auto relocated = new CodeMemBlock();
	// idk about arm thumb stuff help me
	auto originBuffer = (void*)((uint64_t)m_address + 1);
	auto relocatedBuffer = (void*)m_trampoline;

	GenRelocateCodeAndBranch(originBuffer, relocatedBuffer, origin, relocated);

	if (relocated->size == 0) {
		return Err("Failed to relocate original function");
	}

	return Ok(RelocateReturn{
		.m_trampolineOffset = (uint64_t)relocated->size,
		.m_originalOffset = (uint64_t)origin->size,
	});
}

void Arm7HandlerGenerator::relocateInstruction(cs_insn* insn, uint64_t& trampolineAddress, uint64_t& originalAddress) {
	// Dobby handles the relocation of instructions
}

std::vector<uint8_t> Arm7HandlerGenerator::handlerBytes(uint64_t address) {
	Arm7Assembler a(address);
	using enum Arm7Register;

	// preserve registers
	a.push({R0, R1, R2, R3});
	a.vpush({D0, D1, D2, D3});

	// set the parameters
	a.ldr(R0, "content");
	a.mov(R1, LR);

	// call the pre handler, incrementing
	a.ldr(R2, "handlerPre");
	a.blx(R2);
	a.mov(LR, R0);

	// recover registers
	a.vpop({D0, D1, D2, D3});
	a.pop({R0, R1, R2, R3});

	// call the func
	a.blx(LR);

	// preserve the return values
	a.push({R0, R1});

	// call the post handler, decrementing
	a.ldr(R0, "handlerPost");
	a.blx(R0);

	// recover the original return
	a.mov(LR, R0);

	// recover the return values
	a.pop({R0, R1});

	// done!
	a.bx(LR);

	a.label("handlerPre");
	a.write32(reinterpret_cast<uint64_t>(preHandler));

	a.label("handlerPost");
	a.write32(reinterpret_cast<uint64_t>(postHandler));

	a.label("content");
	a.write32(reinterpret_cast<uint64_t>(m_content));

	a.updateLabels();

	return std::move(a.m_buffer);
}

std::vector<uint8_t> Arm7HandlerGenerator::intervenerBytes(uint64_t address) {
	Arm7Assembler a(address);
	using enum Arm7Register;

	a.ldrw(PC, "handler");
	a.label("handler");
	a.write32(reinterpret_cast<uint64_t>(m_handler));

	a.updateLabels();

	return std::move(a.m_buffer);
}

std::vector<uint8_t> Arm7HandlerGenerator::trampolineBytes(uint64_t address, size_t offset) {
	Arm7Assembler a(address);
	using enum Arm7Register;

	a.ldrw(PC, "original");
	a.label("original");
	a.write32(reinterpret_cast<uint64_t>(m_address) + offset);

	a.updateLabels();

	return std::move(a.m_buffer);
}

Result<> Arm7HandlerGenerator::generateTrampoline(RelocateReturn offsets) {
	// Dobby handles the creation of the trampoline
	return Ok();
}