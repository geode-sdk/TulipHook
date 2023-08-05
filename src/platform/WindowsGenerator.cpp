#include "WindowsGenerator.hpp"

#include "../Handler.hpp"
#include "../assembler/X86Assembler.hpp"
#include "PlatformTarget.hpp"

#include <CallingConvention.hpp>
#include <sstream>

using namespace tulip::hook;

#if defined(TULIP_HOOK_WINDOWS)

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

RegMem32 m;
using enum X86Register;

std::vector<uint8_t> WindowsHandlerGenerator::handlerBytes(uint64_t address) {
	X86Assembler a(address);

	// idk what this is for
	for (int i = 0; i < 10; ++i)
		a.nop();

	// generateIntoDefault()

	a.push(ESI);

	// set the parameters
	a.mov(EAX, reinterpret_cast<uintptr_t>(m_content));
	a.push(EAX);

	// call the pre handler, incrementing
	a.mov(EAX, reinterpret_cast<uintptr_t>(preHandler));
	a.call(EAX);

	a.add(ESP, 4);

	size_t stackSize = 0;
	for (auto& param : m_metadata.m_abstract.m_parameters) {
		stackSize += (param.m_size + 3) / 4 * 4;
	}
	// struct return
	if (m_metadata.m_abstract.m_return.m_size > 4 * 2) {
		stackSize += 4;
	}

	// push the stack params
	for (size_t i = 0; i < stackSize; i += 4) {
		// esp points to the topmost member in the stack, so since we have
		// pushed two things on the stack since our original cconv pushes
		// we now must dig those back up from stackSize + 4
		// the reason it's not stackSize + 8 is because stackSize is 4
		// larger than where we need to start to dig up
		// for example, if only ecx is used (thiscall with no extra params)
		// then if nothing was pushed afterwards, ecx would be found at [esp]
		// but the stack size would be 4; and if there were more parameters
		// then the stack size would be 4 larger than where we want to start
		// digging up
		a.push(m[ESP + stackSize]);
	}

	// call cdecl
	a.call(EAX);

	// stack cleanup
	a.add(ESP, stackSize);

	// preserve the return values

	// save space on the stack for them
	a.sub(ESP, 0x14);

	a.mov(m[ESP + 0x10], EAX);
	a.movsd(m[ESP], XMM0);

	// call the post handler, decrementing
	a.mov(EAX, reinterpret_cast<uintptr_t>(postHandler));
	a.call(EAX);

	// recover the return values
	a.mov(EAX, m[ESP + 0x10]);
	a.movsd(XMM0, m[ESP]);

	// give back to the earth what it gave to you
	a.add(ESP, 0x14);

	a.pop(ESI);

	// generateDefaultCleanup()

	return std::move(a.m_buffer);
}

std::vector<uint8_t> WindowsHandlerGenerator::intervenerBytes(uint64_t address) {
	X86Assembler a(address);

	a.jmp(reinterpret_cast<uintptr_t>(m_handler));

	return std::move(a.m_buffer);
}

std::vector<uint8_t> WindowsHandlerGenerator::trampolineBytes(uint64_t address, size_t offset) {
	X86Assembler a(address);

	a.jmp(reinterpret_cast<uintptr_t>(m_address) + offset);

	return std::move(a.m_buffer);
}

std::vector<uint8_t> WindowsWrapperGenerator::wrapperBytes(uint64_t address) {
	X86Assembler a(address);

	// out << m_metadata.m_convention->generateIntoOriginal(m_metadata.m_abstract) << "\n ";

	a.mov(EAX, reinterpret_cast<uintptr_t>(m_address));
	a.call(EAX);

	// out << m_metadata.m_convention->generateOriginalCleanup(m_metadata.m_abstract);

	return std::move(a.m_buffer);
}

std::vector<uint8_t> WindowsWrapperGenerator::reverseWrapperBytes(uint64_t address) {
	X86Assembler a(address);

	// out << m_metadata.m_convention->generateIntoDefault(m_metadata.m_abstract) << "\n ";

	a.mov(EAX, reinterpret_cast<uintptr_t>(m_address));
	a.call(EAX);

	// out << m_metadata.m_convention->generateDefaultCleanup(m_metadata.m_abstract);

	return std::move(a.m_buffer);
}

Result<void*> WindowsWrapperGenerator::generateWrapper() {
	auto code = this->wrapperBytes(reinterpret_cast<uintptr_t>(m_address));
	auto areaSize = (code.size() + (0x20 - code.size()) % 0x20);
	TULIP_HOOK_UNWRAP_INTO(auto area, PlatformTarget::get().allocateArea(areaSize));

	std::memcpy(area, code.data(), code.size());

	return Ok(area);
}

Result<void*> WindowsWrapperGenerator::generateReverseWrapper() {
	auto code = this->reverseWrapperBytes(reinterpret_cast<uintptr_t>(m_address));
	auto areaSize = (code.size() + (0x20 - code.size()) % 0x20);
	TULIP_HOOK_UNWRAP_INTO(auto area, PlatformTarget::get().allocateArea(areaSize));

	std::memcpy(area, code.data(), code.size());

	return Ok(area);
}

#endif
