#include "ArmV8Generator.hpp"

#include "../Handler.hpp"
#include "../assembler/ArmV8Assembler.hpp"
#include "../target/PlatformTarget.hpp"

#include <InstructionRelocation/InstructionRelocation.h>

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

std::vector<uint8_t> ArmV8HandlerGenerator::handlerBytes(uint64_t address) {
    ArmV8Assembler a(address);
    using enum ArmV8Register;

    // preserve registers
	a.push({X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15});
	a.push({D0, D1, D2, D3, D4, D5, D6, D7});
	// v8-15 are callee saved.
	a.push({D16, D17, D18, D19, D20, D21, D22, D23, D24, D25, D26, D27, D28, D29, D30, D31});

	// set the parameters
	a.ldr(X0, "content");
	a.mov(X1, X30);

	// call the pre handler, incrementing
	a.ldr(X2, "handlerPre");
	a.blr(X2);
	a.mov(X30, X0);

	// recover registers
	a.pop({D16, D17, D18, D19, D20, D21, D22, D23, D24, D25, D26, D27, D28, D29, D30, D31});
	a.pop({D0, D1, D2, D3, D4, D5, D6, D7});
	a.pop({X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15});

	// call the func
	a.blr(X30);

	// preserve the return values
	a.push({X0, X1, X2, X3, X4, X5, X6, X7});
	a.push({D0, D1, D2, D3, D4, D5, D6, D7});

	// call the post handler, decrementing
	a.ldr(X0, "handlerPost");
	a.blr(X0);

	// recover the original return
	a.mov(X30, X0);

	// recover the return values
	a.pop({D0, D1, D2, D3, D4, D5, D6, D7});
	a.pop({X0, X1, X2, X3, X4, X5, X6, X7});

	// done!
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
		// Align to 8 bytes for ldr.
		if (address & 7) {
			a.nop();
		}

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
