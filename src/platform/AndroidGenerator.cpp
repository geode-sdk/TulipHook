#include "AndroidGenerator.hpp"

#include "../Handler.hpp"
// #include "../assembler/ArmAssembler.hpp"
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

void AndroidHandlerGenerator::relocateInstruction(cs_insn* insn, uint64_t& trampolineAddress, uint64_t& originalAddress) {}

std::vector<uint8_t> AndroidHandlerGenerator::handlerBytes(uint64_t address) {
	return {};
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