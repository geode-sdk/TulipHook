#include "ArmV7Generator.hpp"

#include "../Handler.hpp"
#include "../assembler/ThumbV7Assembler.hpp"
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

std::vector<uint8_t> ArmV7Generator::handlerBytes(int64_t original, int64_t handler, void* content, HandlerMetadata const& metadata) {
	ThumbV7Assembler a((uint64_t)Target::get().getRealPtr((void*)handler));
	using enum ArmV7Register;

	// preserve registers
	a.pushw({R4, R5, R11, LR});
	a.mov(R11, SP);
	a.sub(SP, SP, 0x70);

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

	// convert the current cc into the default cc
	metadata.m_convention->generateIntoDefault(a, metadata.m_abstract);

	// call the func
	a.blx(R4);

	metadata.m_convention->generateDefaultCleanup(a, metadata.m_abstract);

	// preserve the return values
	a.str(R0, SP, 0x00);

	// call the post handler, decrementing
	a.ldr(R0, "handlerPost");
	a.blx(R0);

	// recover the return values
	a.ldr(R0, SP, 0x00);

	// done!
	a.add(SP, SP, 0x70);
	a.popw({R4, R5, R11, PC});

	a.label("handlerPre");
	a.write32(reinterpret_cast<uint64_t>(preHandler));

	a.label("handlerPost");
	a.write32(reinterpret_cast<uint64_t>(postHandler));

	a.label("content");
	a.write32(reinterpret_cast<uint64_t>(content));

	a.updateLabels();

	return std::move(a.m_buffer);
}
std::vector<uint8_t> ArmV7Generator::intervenerBytes(int64_t original, int64_t handler, size_t size) {
	ThumbV7Assembler a((uint64_t)Target::get().getRealPtr((void*)original));
	ArmV7Assembler aA((uint64_t)Target::get().getRealPtr((void*)original));
	using enum ArmV7Register;

	if (original & 0x1) {
		// thumb
		a.ldr(PC, PC, 0);

		// my thumbs will eat me
		a.write32(handler | 1);

		while (a.m_buffer.size() < size) {
			a.nop();
		}

		return std::move(a.m_buffer);
	}
	else {
		// arm
		aA.ldr(PC, PC, -4);

		// my thumbs are already eating me
		aA.write32(handler | 1);

		return std::move(a.m_buffer);
	}
}
geode::Result<BaseGenerator::RelocateReturn> ArmV7Generator::relocatedBytes(int64_t original, int64_t relocated, std::span<uint8_t const> originalBuffer, size_t targetSize) {
	auto originMem = new CodeMemBlock(Target::get().getRealPtr((void*)original), targetSize);
	auto relocatedMem = new CodeMemBlock();
	// idk about arm thumb stuff help me
	std::array<uint8_t, 0x100> relocatedBuffer;

	static thread_local std::string error;
	error = "";

	// did i ever told you that i hate dobby?
	GenRelocateCodeAndBranch(const_cast<uint8_t*>(originalBuffer.data()) + 1, relocatedBuffer.data(), originMem, relocatedMem, +[](void* dest, void const* src, size_t size) {
		std::memcpy(dest, src, size);
	});

	if (!error.empty()) {
		return geode::Err(std::move(error));
	}

	if (relocatedMem->size == 0) {
		return geode::Err("Failed to relocate original function");
	}
	std::vector<uint8_t> relocatedBufferVec(relocatedMem->size);
	std::memcpy(relocatedBufferVec.data(), relocatedBuffer.data(), relocatedMem->size);
	return geode::Ok(RelocateReturn{std::move(relocatedBufferVec), originMem->size});
}
