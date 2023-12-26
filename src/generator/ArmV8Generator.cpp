#include "ArmV8Generator.hpp"

#include "../Handler.hpp"
#include "../assembler/ArmV8Assembler.hpp"
#include "../target/PlatformTarget.hpp"

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

Result<ArmV8HandlerGenerator::RelocateReturn> ArmV8HandlerGenerator::relocateOriginal(uint64_t target) {
    // TODO
}

void ArmV8HandlerGenerator::relocateInstruction(cs_insn* insn, uint64_t& trampolineAddress, uint64_t& originalAddress) {
    // Dobby handles the relocation of instructions
}

std::vector<uint8_t> ArmV8HandlerGenerator::handlerBytes(uint64_t address) {
    // TODO
}

std::vector<uint8_t> ArmV8HandlerGenerator::intervenerBytes(uint64_t address) {
    ArmV8Assembler a(address);
    using enum ArmV8Register;

    const auto pageOf = [](uint64_t addr) { return addr & ~0xFFFull; }

    const uint32_t lower12 = (address & 0xFFF);
    const uint32_t offset = pageOf(reinterpret_cast<uint64_t>(m_handler)) - pageOf(address);

    a.adrp(X16, offset);
    a.ldr(X16, X16, lower12);
    a.br(X16);

    return std::move(a.m_buffer);
}

std::vector<uint8_t> ArmV7HandlerGenerator::trampolineBytes(uint64_t address, size_t offset) {
	// Dobby handles the creation of the trampoline
	return {};
}

Result<> ArmV8HandlerGenerator::generateTrampoline(RelocateReturn offsets) {
	// Dobby handles the creation of the trampoline
	return Ok();
}