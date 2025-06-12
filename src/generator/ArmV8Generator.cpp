#include "ArmV8Generator.hpp"

#include "../Handler.hpp"
#include "../assembler/ArmV8Assembler.hpp"
#include "../target/PlatformTarget.hpp"

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
	auto origin = new CodeMemBlock(reinterpret_cast<uint64_t>(m_address), target);
	auto relocated = new CodeMemBlock();
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
