#include "WindowsGenerator.hpp"

#include "../Handler.hpp"
#include "../HolderUtil.hpp"
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

std::string WindowsHandlerGenerator::handlerString() {
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
	sub esp, 0x14

	mov [esp + 0x10], eax
	movsd [esp], xmm0

	; call the post handler, decrementing
	mov eax, [_handlerPost]
	call eax

	; recover the return values
	mov eax, [esp + 0x10]
	movsd xmm0, [esp]

	; give back to the earth what it gave to you
	add esp, 0x14

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

std::string WindowsHandlerGenerator::trampolineString(size_t offset) {
	std::ostringstream out;
	out << "jmp _address" << m_address << "_" << offset;
	return out.str();
}

std::string WindowsWrapperGenerator::wrapperString() {
	std::ostringstream out;
	out << std::hex;
	out << m_metadata.m_convention->generateIntoOriginal(m_metadata.m_abstract) << "\n ";

	out << "mov eax, 0x" << reinterpret_cast<uintptr_t>(m_address) << "\n";
	out << "call eax\n";

	out << m_metadata.m_convention->generateOriginalCleanup(m_metadata.m_abstract);

	return out.str();
}

Result<void*> WindowsWrapperGenerator::generateWrapper() {
	TULIP_HOOK_UNWRAP_INTO(KSHolder ks, PlatformTarget::get().openKeystone());

	size_t count;
	unsigned char* encode;
	size_t size;

	ks_option(ks, KS_OPT_SYM_RESOLVER, reinterpret_cast<size_t>(&Handler::symbolResolver));

	auto code = this->wrapperString();

	auto status = ks_asm(ks, code.c_str(), reinterpret_cast<size_t>(m_address), &encode, &size, &count);
	if (status != KS_ERR_OK) {
		return Err("Assembling wrapper failed: " + std::string(ks_strerror(ks_errno(ks))));
	}

	if (!size && code.size()) {
		return Err("Assembling wrapper failed: Unknown error (no bytes were written)");
	}

	auto areaSize = (size + (0x20 - size) % 0x20);

	TULIP_HOOK_UNWRAP_INTO(auto area, PlatformTarget::get().allocateArea(areaSize));

	std::memcpy(area, encode, size);

	ks_free(encode);

	return Ok(area);
}

#endif
