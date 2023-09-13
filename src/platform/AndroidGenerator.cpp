#include "AndroidGenerator.hpp"

#include "../Handler.hpp"
#include "../assembler/ArmThumbAssembler.hpp"
#include "PlatformTarget.hpp"

#include <CallingConvention.hpp>
#include <sstream>

using namespace tulip::hook;

#if defined(TULIP_HOOK_ANDROID)

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

Result<> AndroidHandlerGenerator::generateHandler() {
	return Err("Not implemented");
}

Result<std::vector<uint8_t>> AndroidHandlerGenerator::generateIntervener() {
	return Err("Not implemented");
}

Result<> AndroidHandlerGenerator::generateTrampoline(RelocateReturn offsets) {
	return Err("Not implemented");
}

Result<AndroidHandlerGenerator::RelocateReturn> AndroidHandlerGenerator::relocateOriginal(uint64_t target) {
	return Err("Not implemented");
}

void AndroidHandlerGenerator::relocateInstruction(cs_insn* insn, uint64_t& trampolineAddress, uint64_t& originalAddress) {
}

std::vector<uint8_t> AndroidHandlerGenerator::handlerBytes(uint64_t address) {
	ArmThumbAssembler a(address);
	using enum ArmRegister;

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

std::vector<uint8_t> AndroidHandlerGenerator::intervenerBytes(uint64_t address) {
	return {};
}

std::vector<uint8_t> AndroidHandlerGenerator::trampolineBytes(uint64_t address, size_t offset) {
	return {};
}

Result<void*> AndroidWrapperGenerator::generateWrapper() {
	return Ok(m_address); // only windows needs the wrapper
}

Result<void*> AndroidWrapperGenerator::generateReverseWrapper() {
	return Ok(m_address); // only windows needs the wrapper
}

std::vector<uint8_t> AndroidWrapperGenerator::wrapperBytes(uint64_t address) {
	return std::vector<uint8_t>();
}

std::vector<uint8_t> AndroidWrapperGenerator::reverseWrapperBytes(uint64_t address) {
	return std::vector<uint8_t>();
}

#endif