#include "ArmV7Generator.hpp"

#include "../Handler.hpp"
#include "../assembler/ArmV7Assembler.hpp"
#include "../target/PlatformTarget.hpp"

#include <CallingConvention.hpp>
#include <InstructionRelocation/InstructionRelocation.h>

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

std::vector<uint8_t> ArmV7HandlerGenerator::handlerBytes(uint64_t address) {
	ArmV7Assembler a((uint64_t)Target::get().getRealPtr((void*)address));
	using enum ArmV7Register;

	// preserve registers
	a.push({R4, LR});
	a.sub(SP, SP, 0x30);

	a.str(R0, SP, 0x00);
	a.str(R1, SP, 0x04);
	a.str(R2, SP, 0x08);
	a.str(R3, SP, 0x0C);
	a.vstr(D0, SP, 0x10);
	a.vstr(D1, SP, 0x18);
	a.vstr(D2, SP, 0x20);
	a.vstr(D3, SP, 0x28);

	// set the parameters
	a.ldr(R0, "content");

	// call the pre handler, incrementing
	a.ldr(R1, "handlerPre");
	a.blx(R1);
	a.mov(R4, R0);

	// recover registers
	a.vldr(D3, SP, 0x28);
	a.vldr(D2, SP, 0x20);
	a.vldr(D1, SP, 0x18);
	a.vldr(D0, SP, 0x10);
	a.ldr(R3, SP, 0x0C);
	a.ldr(R2, SP, 0x08);
	a.ldr(R1, SP, 0x04);
	a.ldr(R0, SP, 0x00);

	// call the func
	a.blx(R4);

	// preserve the return values
	a.str(R0, SP, 0x00);

	// call the post handler, decrementing
	a.ldr(R0, "handlerPost");
	a.blx(R0);

	// recover the return values
	a.ldr(R0, SP, 0x00);

	// done!
	a.add(SP, SP, 0x30);
	a.pop({R4, PC});

	a.label("handlerPre");
	a.write32(reinterpret_cast<uint64_t>(preHandler));

	a.label("handlerPost");
	a.write32(reinterpret_cast<uint64_t>(postHandler));

	a.label("content");
	a.write32(reinterpret_cast<uint64_t>(m_content));

	a.updateLabels();

	return std::move(a.m_buffer);
}

std::vector<uint8_t> ArmV7HandlerGenerator::intervenerBytes(uint64_t address, size_t size) {
	ArmV7Assembler a((uint64_t)Target::get().getRealPtr((void*)address));
	using enum ArmV7Register;

	// align
	if (address & 0x2) {
		a.nop();
	}

	if (address & 0x1) {
		// thumb
		a.ldrw(PC, PC, -4);
	}
	else {
		// arm
		a.ldrArm(PC, PC, -4);
	}
	
	// my thumbs will eat me
	a.write32(reinterpret_cast<uint64_t>(m_handler) + 1);

	a.updateLabels();

	return std::move(a.m_buffer);
}

geode::Result<HandlerGenerator::TrampolineReturn> ArmV7HandlerGenerator::generateTrampoline(uint64_t target) {
	auto origin = new CodeMemBlock((uint64_t)Target::get().getRealPtr(m_address), target);
	auto relocated = new CodeMemBlock();
	// idk about arm thumb stuff help me
	auto originBuffer = m_address;
	auto relocatedBuffer = m_trampoline;

	static thread_local std::string error;
	error = "";

	GenRelocateCodeAndBranch(originBuffer, relocatedBuffer, origin, relocated, +[](void* dest, void const* src, size_t size) {
		auto res = Target::get().writeMemory(dest, src, size);
		if (!res) {
			error = res.unwrapErr();
		}
	});

	if (!error.empty()) {
		return geode::Err(std::move(error));
	}

	if (relocated->size == 0) {
		return geode::Err("Failed to relocate original function");
	}
	return geode::Ok(TrampolineReturn{FunctionData{m_trampoline, relocated->size}, relocated->size});
}
