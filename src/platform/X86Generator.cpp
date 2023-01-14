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
	TULIP_HOOK_UNWRAP_INTO(KSHolder ks, PlatformTarget::get().openKeystone());

	size_t count;
	unsigned char* encode;
	size_t size;

	if (ks_option(ks, KS_OPT_SYM_RESOLVER, reinterpret_cast<size_t>(&Handler::symbolResolver)) != KS_ERR_OK) {
		return Err("Unable to set assembler options for handler: " + std::string(ks_strerror(ks_errno(ks))));
	}

	// for debuggers to not cry
	std::fill_n(reinterpret_cast<char*>(reinterpret_cast<size_t>(m_handler) - 10), 10, '\x90');

	auto code = this->handlerString();

	// std::cout << code << "\n";

	auto status = ks_asm(ks, code.c_str(), reinterpret_cast<size_t>(m_handler), &encode, &size, &count);
	if (status != KS_ERR_OK) {
		return Err("Assembling handler failed: " + std::string(ks_strerror(ks_errno(ks))));
	}

	if (!size && code.size()) {
		return Err("Assembling handler failed: Unknown error (no bytes were written)");
	}
	// std::cout << "size: " << size << "\n";
	// for (auto i = 0; i < size; ++i) {
	// 	std::cout << std::hex << +encode[i] << " ";
	// }
	// std::cout << "\n";

	std::memcpy(m_handler, encode, size);

	ks_free(encode);

	return Ok();
}

Result<std::vector<uint8_t>> X86HandlerGenerator::generateIntervener() {
	TULIP_HOOK_UNWRAP_INTO(KSHolder ks, PlatformTarget::get().openKeystone());

	size_t count;
	unsigned char* encode;
	size_t size;

	ks_option(ks, KS_OPT_SYM_RESOLVER, reinterpret_cast<size_t>(&Handler::symbolResolver));

	auto code = this->intervenerString();

	// std::cout << "intervener: " << code << std::endl;
	auto status = ks_asm(ks, code.c_str(), reinterpret_cast<size_t>(m_address), &encode, &size, &count);
	if (status != KS_ERR_OK) {
		return Err("Assembling intervener failed: " + std::string(ks_strerror(ks_errno(ks))));
	}

	if (!size && code.size()) {
		return Err("Assembling intervener failed: Unknown error (no bytes were written)");
	}
	// std::cout << "size: " << size << "\n";
	// for (auto i = 0; i < size; ++i) {
	// 	std::cout << std::hex << +encode[i] << " ";
	// }
	// std::cout << "\n";

	std::vector<uint8_t> ret(encode, encode + size);

	ks_free(encode);

	return Ok(ret);
}

Result<> X86HandlerGenerator::generateTrampoline(size_t offset) {
	TULIP_HOOK_UNWRAP_INTO(KSHolder ks, PlatformTarget::get().openKeystone());

	size_t count;
	unsigned char* encode;
	size_t size;

	ks_option(ks, KS_OPT_SYM_RESOLVER, reinterpret_cast<size_t>(&Handler::symbolResolver));

	auto code = this->trampolineString(offset);
	auto address = reinterpret_cast<size_t>(m_trampoline) + offset;

	// std::cout << "trampoline: " << code << std::endl;
	auto status = ks_asm(ks, code.c_str(), address, &encode, &size, &count);
	if (status != KS_ERR_OK) {
		return Err("Assembling trampoline failed: " + std::string(ks_strerror(ks_errno(ks))));
	}

	if (!size && code.size()) {
		return Err("Assembling trampoline failed: Unknown error (no bytes were written)");
	}

	std::memcpy(reinterpret_cast<void*>(address), encode, size);

	ks_free(encode);

	return Ok();
}

Result<size_t> X86HandlerGenerator::relocateOriginal(size_t target) {
	// std::memcpy(m_trampoline, m_address, 32);
	size_t offset = 0;

	TULIP_HOOK_UNWRAP_INTO(CSHolder cs, PlatformTarget::get().openCapstone());

	cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

	auto insn = cs_malloc(cs);

	uint64_t address = reinterpret_cast<uint64_t>(m_trampoline);
	uint8_t const* code = reinterpret_cast<uint8_t const*>(m_address);
	size_t size = 32;

	// for debuggers to not cry
	std::fill_n(reinterpret_cast<char*>(address - 10), 10, '\x90');

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

	return Ok(originalAddress - reinterpret_cast<uint64_t>(m_address));
}

std::string X86HandlerGenerator::intervenerString() {
	std::ostringstream out;

	out << "jmp _handler" << m_address;

	return out.str();
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

	if (relativeGroup && detail->x86.encoding.imm_offset != 0) {
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
	}
	else {
		trampolineAddress += size;
	}
	originalAddress += size;
}

#endif
