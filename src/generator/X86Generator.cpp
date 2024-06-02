#include "X86Generator.hpp"

#include "../Handler.hpp"
#include "../assembler/X86Assembler.hpp"
#include "../target/PlatformTarget.hpp"

#include <CallingConvention.hpp>
#include <capstone/capstone.h>
#include <sstream>

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

RegMem32 m;
using enum X86Register;

std::vector<uint8_t> X86HandlerGenerator::handlerBytes(uint64_t address) {
	X86Assembler a(address);

	// idk what this is for
	for (int i = 0; i < 10; ++i) {
		a.nop();
	}

	m_metadata.m_convention->generateIntoDefault(a, m_metadata.m_abstract);

	a.push(ESI);

	// set the parameters
	a.mov(EAX, reinterpret_cast<uintptr_t>(m_content));
	a.push(EAX);

	// call the pre handler, incrementing
	a.call(reinterpret_cast<uintptr_t>(preHandler));

	a.add(ESP, 4);

	size_t stackSize = 0;
	for (auto& param : m_metadata.m_abstract.m_parameters) {
		stackSize += (param.m_size + 3) / 4 * 4;
	}
	// struct return
	if (m_metadata.m_abstract.m_return.m_kind == AbstractTypeKind::Other) {
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
	a.call(reinterpret_cast<uintptr_t>(postHandler));

	// recover the return values
	a.mov(EAX, m[ESP + 0x10]);
	a.movsd(XMM0, m[ESP]);

	// give back to the earth what it gave to you
	a.add(ESP, 0x14);

	a.pop(ESI);

	m_metadata.m_convention->generateDefaultCleanup(a, m_metadata.m_abstract);

	return std::move(a.m_buffer);
}

std::vector<uint8_t> X86HandlerGenerator::intervenerBytes(uint64_t address) {
	X86Assembler a(address);

	a.jmp(reinterpret_cast<uintptr_t>(m_handler));

	return std::move(a.m_buffer);
}

std::vector<uint8_t> X86HandlerGenerator::trampolineBytes(uint64_t address, size_t offset) {
	X86Assembler a(address);

	a.jmp(reinterpret_cast<uintptr_t>(m_address) + offset);

	return std::move(a.m_buffer);
}

std::vector<uint8_t> X86WrapperGenerator::wrapperBytes(uint64_t address) {
	X86Assembler a(address);

	m_metadata.m_convention->generateIntoOriginal(a, m_metadata.m_abstract);

	a.call(reinterpret_cast<uintptr_t>(m_address));

	m_metadata.m_convention->generateOriginalCleanup(a, m_metadata.m_abstract);

	return std::move(a.m_buffer);
}

std::vector<uint8_t> X86WrapperGenerator::reverseWrapperBytes(uint64_t address) {
	X86Assembler a(address);

	m_metadata.m_convention->generateIntoDefault(a, m_metadata.m_abstract);

	a.call(reinterpret_cast<uintptr_t>(m_address));

	m_metadata.m_convention->generateDefaultCleanup(a, m_metadata.m_abstract);

	return std::move(a.m_buffer);
}

Result<void*> X86WrapperGenerator::generateWrapper() {
	if (!m_metadata.m_convention->needsWrapper(m_metadata.m_abstract)) {
		return Ok(m_address);
	}
	
	// this is silly, butt
	auto codeSize = this->wrapperBytes(0).size();
	auto areaSize = (codeSize + (0x20 - codeSize) % 0x20);

	TULIP_HOOK_UNWRAP_INTO(auto area, Target::get().allocateArea(areaSize));
	auto code = this->wrapperBytes(reinterpret_cast<uintptr_t>(area));

	TULIP_HOOK_UNWRAP(Target::get().writeMemory(area, code.data(), codeSize));

	return Ok(area);
}

Result<void*> X86WrapperGenerator::generateReverseWrapper() {
	if (!m_metadata.m_convention->needsWrapper(m_metadata.m_abstract)) {
		return Ok(m_address);
	}

	// this is silly, butt
	auto codeSize = this->reverseWrapperBytes(0).size();
	auto areaSize = (codeSize + (0x20 - codeSize) % 0x20);

	TULIP_HOOK_UNWRAP_INTO(auto area, Target::get().allocateArea(areaSize));
	auto code = this->reverseWrapperBytes(reinterpret_cast<uintptr_t>(area));

	TULIP_HOOK_UNWRAP(Target::get().writeMemory(area, code.data(), codeSize));

	return Ok(area);
}

Result<X86HandlerGenerator::RelocateReturn> X86HandlerGenerator::relocateOriginal(uint64_t target) {
	// memcpy(m_trampoline, m_address, 32);

	TULIP_HOOK_UNWRAP_INTO(auto cs, Target::get().openCapstone());

	cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

	auto insn = cs_malloc(cs);

	uint64_t address = reinterpret_cast<uint64_t>(m_trampoline);
	uint8_t const* code = reinterpret_cast<uint8_t const*>(m_address);
	size_t size = 32;

	auto difference = reinterpret_cast<uint64_t>(m_trampoline) - reinterpret_cast<uint64_t>(m_address);

	auto targetAddress = address + target;

	auto originalAddress = reinterpret_cast<uint64_t>(m_address);
	auto trampolineAddress = reinterpret_cast<uint64_t>(m_trampoline);
	std::array<uint8_t, 64> buffer;

	while (cs_disasm_iter(cs, &code, &size, &address, insn)) {
		if (insn->address >= targetAddress) {
			break;
		}
		auto bufferOffset = trampolineAddress - reinterpret_cast<uint64_t>(m_trampoline);

		TULIP_HOOK_UNWRAP(this->relocateInstruction(insn, buffer.data() + bufferOffset, trampolineAddress, originalAddress));
	}

	cs_free(insn, 1);

	Target::get().closeCapstone();

	auto bufferOffset = trampolineAddress - reinterpret_cast<uint64_t>(m_trampoline);
	TULIP_HOOK_UNWRAP(Target::get().writeMemory(m_trampoline, buffer.data(), bufferOffset));

	return Ok(RelocateReturn{
		.m_trampolineOffset = trampolineAddress - reinterpret_cast<uint64_t>(m_trampoline),
		.m_originalOffset = originalAddress - reinterpret_cast<uint64_t>(m_address),
	});
}

Result<> X86HandlerGenerator::relocateInstruction(cs_insn* insn, uint8_t* buffer, uint64_t& trampolineAddress, uint64_t& originalAddress) {
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

	std::memcpy(buffer, insn->bytes, size);

	// branches, jumps, calls
	if (detail->x86.encoding.imm_offset != 0 && relativeGroup) {
		intptr_t jmpTargetAddr = static_cast<intptr_t>(detail->x86.operands[0].imm) -
		static_cast<intptr_t>(trampolineAddress) + static_cast<intptr_t>(originalAddress);

		return this->relocateBranchInstruction(insn, buffer, trampolineAddress, originalAddress, jmpTargetAddr);
	}

	if (detail->x86.encoding.disp_offset != 0) {
		// [rip + 0xval]s
		auto& operand0 = detail->x86.operands[0];
		if (operand0.type == X86_OP_MEM && operand0.mem.base == X86_REG_RIP) {
			auto disp = operand0.mem.disp;
			return this->X86HandlerGenerator::relocateRIPInstruction(insn, buffer, trampolineAddress, originalAddress, disp);
		}

		auto& operand1 = detail->x86.operands[1];
		if (operand1.type == X86_OP_MEM && operand1.mem.base == X86_REG_RIP) {
			auto disp = operand1.mem.disp;
			return this->relocateRIPInstruction(insn, buffer, trampolineAddress, originalAddress, disp);
		}
	}

	trampolineAddress += size;
	originalAddress += size;
	return Ok();
}

Result<> X86HandlerGenerator::relocateRIPInstruction(cs_insn* insn, uint8_t* buffer, uint64_t& trampolineAddress, uint64_t& originalAddress, int64_t disp) {
	auto const id = insn->id;
	auto const detail = insn->detail;
	auto const address = insn->address;
	auto const size = insn->size;
	auto difference = static_cast<intptr_t>(trampolineAddress) - static_cast<intptr_t>(originalAddress);

	if (difference > 0x7fffffffll || difference < -0x80000000ll) {
		return Err("rip displacement too large");
	}

	// std::cout << "short disp: " << disp << std::endl;
	// std::cout << "difference: " << difference << std::endl;

	int addrBytes = disp - difference;
	auto offset = detail->x86.encoding.disp_offset;

	std::memcpy(buffer + offset, &addrBytes, sizeof(int));

	trampolineAddress += size;
	originalAddress += size;
	return Ok();
}

Result<> X86HandlerGenerator::relocateBranchInstruction(cs_insn* insn, uint8_t* buffer, uint64_t& trampolineAddress, uint64_t& originalAddress, int64_t targetAddress) {
	// std::cout << "testing the disp value: " << detail->x86.operands[0].imm << std::endl;
	auto difference = static_cast<intptr_t>(trampolineAddress) - static_cast<intptr_t>(originalAddress);
	
	if (difference > 0x7fffffffll || difference < -0x80000000ll) {
		return Err("branch displacement too large");
	}

	if (id == X86_INS_JMP) {
		// res = dst - src - 5
		std::array<uint8_t, 5> jmp = {0xe9, 0, 0, 0, 0};
		int addrBytes = jmpTargetAddr - trampolineAddress - 5;
		std::memcpy(jmp.data() + 1, &addrBytes, sizeof(int));
		std::memcpy(buffer, jmp.data(), jmp.size());

		trampolineAddress += 5;
	}
	else if (id == X86_INS_CALL) {
		// res = dst - src - 5
		std::array<uint8_t, 5> call = {0xe8, 0, 0, 0, 0};
		int addrBytes = jmpTargetAddr - trampolineAddress - 5;
		std::memcpy(call.data() + 1, &addrBytes, sizeof(int));
		std::memcpy(buffer, call.data(), call.size());

		trampolineAddress += 5;
	}
	else {
		// conditional jumps
		// res = dst - src - 6
		std::array<uint8_t, 6> jmp = {0x0f, 0, 0, 0, 0, 0};
		int addrBytes = jmpTargetAddr - trampolineAddress - 6;
		if (size == 2) {
			jmp[1] = insn->bytes[0] + 0x10;
		}
		else {
			jmp[1] = insn->bytes[1];
		}
		std::memcpy(jmp.data() + 2, &addrBytes, sizeof(int));
		std::memcpy(buffer, jmp.data(), jmp.size());

		trampolineAddress += 6;
	}

	originalAddress += size;
	return Ok();
}