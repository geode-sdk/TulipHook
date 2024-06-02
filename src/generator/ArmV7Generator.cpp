#include "ArmV7Generator.hpp"

#include "../Handler.hpp"
#include "../assembler/ArmV7Assembler.hpp"
#include "../target/PlatformTarget.hpp"

#include <CallingConvention.hpp>
#include <InstructionRelocation/InstructionRelocation.h>
#include <sstream>
#include <iostream>

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

std::vector<uint8_t> ArmV7HandlerGenerator::handlerBytes(uint64_t address) {
	ArmV7Assembler a((uint64_t)Target::get().getRealPtr((void*)address));
	using enum ArmV7Register;

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

std::vector<uint8_t> ArmV7HandlerGenerator::intervenerBytes(uint64_t address) {
	ArmV7Assembler a((uint64_t)Target::get().getRealPtr((void*)address));
	using enum ArmV7Register;

	// align
	if (address & 0x2) {
		a.nop();
	}

	if (address & 0x1) {
		// thumb
		a.ldrpcn();
	}
	else {
		// arm
		a.ldrpcn2();
	}
	
	// my thumbs will eat me
	a.write32(reinterpret_cast<uint64_t>(m_handler) + 1);

	a.updateLabels();

	return std::move(a.m_buffer);
}

Result<> ArmV7HandlerGenerator::generateTrampoline(uint64_t target) {
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
			error = res.error();
		}
	});

	if (!error.empty()) {
		return Err(std::move(error));
	}

	if (relocated->size == 0) {
		return Err("Failed to relocate original function");
	}
	return Ok();
}
