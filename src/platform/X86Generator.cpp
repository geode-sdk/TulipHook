#include "../Handler.hpp"
#include "../HolderUtil.hpp"
#include "PlatformGenerator.hpp"
#include "PlatformTarget.hpp"

#include <CallingConvention.hpp>
#include <iostream>
#include <sstream>
#include <stdexcept>

using namespace tulip::hook;

#if defined(TULIP_HOOK_MACOS)
using X86HandlerGenerator = MacosHandlerGenerator;
using X86WrapperGenerator = MacosWrapperGenerator;
#elif defined(TULIP_HOOK_WINDOWS)
using X86HandlerGenerator = WindowsHandlerGenerator;
using X86WrapperGenerator = WindowsWrapperGenerator;
#endif

#if defined(TULIP_HOOK_MACOS) || defined(TULIP_HOOK_WINDOWS)

Result<> X86HandlerGenerator::generateHandler() {
	auto address = reinterpret_cast<uint64_t>(m_handler);
	auto encode = this->handlerBytes(address);

	std::memcpy(m_handler, encode.data(), encode.size());

	return Ok();
}

Result<std::vector<uint8_t>> X86HandlerGenerator::generateIntervener() {
	auto address = reinterpret_cast<uint64_t>(m_address);
	auto encode = this->intervenerBytes(address);

	return Ok(std::move(encode));
}

Result<> X86HandlerGenerator::generateTrampoline(RelocateReturn offsets) {
	auto address = reinterpret_cast<uint64_t>(m_trampoline) + offsets.m_trampolineOffset;
	auto encode = this->trampolineBytes(address, offsets.m_originalOffset);

	std::memcpy(reinterpret_cast<void*>(address), encode.data(), encode.size());

	return Ok();
}

Result<X86HandlerGenerator::RelocateReturn> X86HandlerGenerator::relocateOriginal(uint64_t target) {
	// std::memcpy(m_trampoline, m_address, 32);

	TULIP_HOOK_UNWRAP_INTO(CSHolder cs, PlatformTarget::get().openCapstone());

	cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

	auto insn = cs_malloc(cs);

	uint64_t address = reinterpret_cast<uint64_t>(m_trampoline);
	uint8_t const* code = reinterpret_cast<uint8_t const*>(m_address);
	size_t size = 32;

	auto difference = reinterpret_cast<uint64_t>(m_trampoline) - reinterpret_cast<uint64_t>(m_address);

	auto targetAddress = address + target;

	auto originalAddress = reinterpret_cast<uint64_t>(m_address);
	auto trampolineAddress = reinterpret_cast<uint64_t>(m_trampoline);

	while (cs_disasm_iter(cs, &code, &size, &address, insn)) {
		if (insn->address >= targetAddress) {
			break;
		}

		this->relocateInstruction(insn, trampolineAddress, originalAddress);
	}

	cs_free(insn, 1);

	return Ok(RelocateReturn{
		.m_trampolineOffset = trampolineAddress - reinterpret_cast<uint64_t>(m_trampoline),
		.m_originalOffset = originalAddress - reinterpret_cast<uint64_t>(m_address),
	});
}

void X86HandlerGenerator::relocateInstruction(cs_insn* insn, uint64_t& trampolineAddress, uint64_t& originalAddress) {
	auto const id = insn->id;
	auto const detail = insn->detail;
	auto const address = insn->address;
	auto const size = insn->size;

	auto relativeGroup = false;
	for (auto i = 0; i < detail->groups_count; ++i) {
		// std::cout << "group of inst: " << +detail->groups[i] << std::endl;
		switch (detail->groups[i]) {
			case X86_GRP_BRANCH_RELATIVE:
			case X86_GRP_CALL:
			case X86_GRP_JUMP: // long conditional jumps are not considered jump (bug i should report) but its not used in gd anyway
				relativeGroup = true;
				break;
			default: break;
		}
	}

	std::memcpy(reinterpret_cast<void*>(trampolineAddress), reinterpret_cast<void*>(originalAddress), size);

	if (detail->x86.encoding.imm_offset != 0) {
		// branches, jumps, calls
		if (relativeGroup) {
			// std::cout << "testing the disp value: " << detail->x86.operands[0].imm << std::endl;
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
				// std::cout << "WARNING: relocating conditional jmp, this is likely broken hehe" << std::endl;
				// conditional jumps
				// long conditional jmp size
				// this is like probably not right idk what instruction this is supposed to be
				int addrBytes = jmpTargetAddr - trampolineAddress - 6;
				std::memcpy(reinterpret_cast<void*>(trampolineAddress + 2), &addrBytes, sizeof(int));
				inBinary[1] = inBinary[0] + 0x10;
				inBinary[0] = 0x0f;

				trampolineAddress += 6;
			}

			originalAddress += size;
			return;
		}
	}

	if (detail->x86.encoding.disp_offset != 0) {
		// [rip + 0xval]s
		for (int i = 0; i < detail->x86.op_count; ++i) {
			auto& operand = detail->x86.operands[i];

			if (operand.type == X86_OP_MEM && operand.mem.base == X86_REG_RIP) {
				auto disp = operand.mem.disp;
				auto difference = static_cast<intptr_t>(trampolineAddress) - static_cast<intptr_t>(originalAddress);

				int addrBytes = disp - difference;
				auto offset = detail->x86.encoding.disp_offset;

				std::memcpy(reinterpret_cast<void*>(trampolineAddress + offset), &addrBytes, sizeof(int));

				trampolineAddress += size;
				originalAddress += size;
				return;
			}
		}
	}

	trampolineAddress += size;
	originalAddress += size;
}

#endif
