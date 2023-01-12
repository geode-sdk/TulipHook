#include "WindowsGenerator.hpp"

#include "../Handler.hpp"
#include "PlatformTarget.hpp"

#include <CallingConvention.hpp>
#include <iostream>
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

std::string WindowsGenerator::handlerString() {
	std::ostringstream out;
	out << std::hex;
	// out << "int3\n";
	out << m_metadata.m_convention->generateIntoDefault(m_metadata.m_abstract) << "\n ";

	// increment and get function
	out << R"ASM(
	push esi

	; set the parameters
	mov eax, [_content]
	push eax
	
	; call the pre handler, incrementing
	mov eax, [_handlerPre]
	call eax

	; cdecl is caller cleanup
	add esp, 0x4
)ASM";

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
		out << "push [esp + 0x" << stackSize << "]\n";
	}

	// call cdecl
	out << "call eax\n";

	// fix stack
	out << "add esp, 0x" << stackSize << "\n";

	// decrement and return eax and edx
	out << R"ASM(
	; preserve the return values

	; save space on stack for them
	sub esp, 0xc

	mov [esp + 0x10], eax
	movsd [esp], xmm0

	; call the post handler, decrementing
	mov eax, [_handlerPost]
	call eax

	; recover the return values
	mov eax, [esp + 0x10]
	movsd xmm0, [esp]

	; give back to the earth what it gave to you
	add esp, 0xc

	pop esi
)ASM";

	out << m_metadata.m_convention->generateDefaultCleanup(m_metadata.m_abstract);

	out << R"ASM(
_handlerPre: 
	dd 0x)ASM"
		<< reinterpret_cast<uintptr_t>(preHandler);

	out << R"ASM(
_handlerPost: 
	dd 0x)ASM"
		<< reinterpret_cast<uintptr_t>(postHandler);

	out << R"ASM(
_content: 
	dd 0x)ASM"
		<< reinterpret_cast<uintptr_t>(m_content);

	return out.str();
}

std::string WindowsGenerator::trampolineString(size_t offset) {
	std::ostringstream out;
	out << "jmp _address" << m_address << "_" << offset;
	return out.str();
}

void WindowsGenerator::relocateInstruction(cs_insn* insn, uint64_t& trampolineAddress, uint64_t& originalAddress) {
	auto id = insn->id;
	auto detail = insn->detail;
	auto address = insn->address;
	auto size = insn->size;

	auto jumpGroup = false;
	for (auto i = 0; i < detail->groups_count; ++i) {
		if (detail->groups[i] == X86_GRP_JUMP) {
			jumpGroup = true;
			break;
		}
	}

	std::memcpy(reinterpret_cast<void*>(trampolineAddress), reinterpret_cast<void*>(originalAddress), size);

	if (jumpGroup) {
		intptr_t jmpTargetAddr = static_cast<intptr_t>(detail->x86.operands[0].imm) -
			static_cast<intptr_t>(trampolineAddress) + static_cast<intptr_t>(originalAddress);
		uint8_t* inBinary = reinterpret_cast<uint8_t*>(trampolineAddress);

		if (id == X86_INS_JMP) {
			// res = dst - src - 5
			int addrBytes = jmpTargetAddr - trampolineAddress - 5;
			std::memcpy(reinterpret_cast<void*>(trampolineAddress + 1), &addrBytes, sizeof(int));
			inBinary[0] = 0xe9;

			trampolineAddress += 5;
		}
		else if (id == X86_INS_CALL) {
			// res = dst - src - 5
			int addrBytes = jmpTargetAddr - trampolineAddress - 5;
			std::memcpy(reinterpret_cast<void*>(trampolineAddress + 1), &addrBytes, sizeof(int));
			inBinary[0] = 0xe8;

			trampolineAddress += 5;
		}
		else {
			std::cout << "WARNING: relocating conditional jmp, this is likely broken hehe" << std::endl;
			// conditional jumps
			// long conditional jmp size
			// this is like probably not right idk what instruction this is supposed to be
			int addrBytes = jmpTargetAddr - trampolineAddress - 6;
			std::memcpy(reinterpret_cast<void*>(trampolineAddress + 2), &addrBytes, sizeof(int));
			inBinary[1] = inBinary[0] + 0x10;
			inBinary[0] = 0x0f;

			trampolineAddress += 6;
		}
	}
	else {
		trampolineAddress += size;
	}
	originalAddress += size;
}

#endif
