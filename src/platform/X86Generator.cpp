#include "PlatformGenerator.hpp"
#include "PlatformTarget.hpp"
#include "../Handler.hpp"

#include <sstream>
#include <stdexcept>

#include <CallingConvention.hpp>

#include <iostream>

using namespace tulip::hook;

#if defined(TULIP_HOOK_MACOS)
using X86Generator = MacosGenerator;
#elif defined(TULIP_HOOK_WINDOWS)
using X86Generator = WindowsGenerator;
#endif

#if defined(TULIP_HOOK_MACOS) || defined(TULIP_HOOK_WINDOWS)

template<class T, auto Fun>
struct RAIIHolder {
	T m_engine;

	RAIIHolder(T engine) : m_engine(engine) {}
	~RAIIHolder() {
		Fun();
	}
	operator T() {
		return m_engine;
	}
};
static void keystoneCloseFun() {
	PlatformTarget::get().closeKeystone();
};
using KSHolder = RAIIHolder<ks_engine*, &keystoneCloseFun>;
static void capstoneCloseFun() {
	PlatformTarget::get().closeCapstone();
};
using CSHolder = RAIIHolder<csh, &capstoneCloseFun>;

Result<> X86Generator::generateHandler() {

	TULIP_UNWRAP_INTO(KSHolder ks, PlatformTarget::get().openKeystone());

	size_t count;
	unsigned char* encode;
	size_t size;

	ks_option(ks, KS_OPT_SYM_RESOLVER, reinterpret_cast<size_t>(&Handler::symbolResolver));

	auto code = this->handlerString();

	std::cout << code << "\n";

	// std::cout << "handler: " << code << std::endl;
	auto status = ks_asm(ks, code.c_str(), reinterpret_cast<size_t>(m_handler), &encode, &size, &count);
	if (status != KS_ERR_OK) {
		return Err(
			"Assembling handler failed: " + 
			std::string(ks_strerror(ks_errno(ks)))
		);
	}

	std::memcpy(m_handler, encode, size);

	ks_free(encode);

	return Ok();
}
Result<std::vector<uint8_t>> X86Generator::generateIntervener() {

	TULIP_UNWRAP_INTO(KSHolder ks, PlatformTarget::get().openKeystone());

	size_t count;
	unsigned char* encode;
	size_t size;

	ks_option(ks, KS_OPT_SYM_RESOLVER, reinterpret_cast<size_t>(&Handler::symbolResolver));

	auto code = this->intervenerString();

	// std::cout << "intervener: " << code << std::endl;
	auto status = ks_asm(ks, code.c_str(), reinterpret_cast<size_t>(m_address), &encode, &size, &count);
	if (status != KS_ERR_OK) {
		return Err(
			"Assembling intervener failed: " + 
			std::string(ks_strerror(ks_errno(ks)))
		);
	}

	std::vector<uint8_t> ret(encode, encode + size);

	ks_free(encode);

	return Ok(ret);
}
Result<> X86Generator::generateTrampoline(size_t offset) {

	TULIP_UNWRAP_INTO(KSHolder ks, PlatformTarget::get().openKeystone());

	size_t count;
	unsigned char* encode;
	size_t size;

	ks_option(ks, KS_OPT_SYM_RESOLVER, reinterpret_cast<size_t>(&Handler::symbolResolver));

	auto code = this->trampolineString(offset);
	auto address = reinterpret_cast<size_t>(m_trampoline) + offset;

	// std::cout << "handler: " << code << std::endl;
	auto status = ks_asm(ks, code.c_str(), address, &encode, &size, &count);
	if (status != KS_ERR_OK) {
		return Err(
			"Assembling trampoline failed: " + 
			std::string(ks_strerror(ks_errno(ks)))
		);
	}

	std::memcpy(reinterpret_cast<void*>(address), encode, size);

	ks_free(encode);

	return Ok();

}
Result<size_t> X86Generator::relocateOriginal(size_t target) {
	std::memcpy(m_trampoline, m_address, 32);
	size_t offset = 0;

	TULIP_UNWRAP_INTO(CSHolder cs, PlatformTarget::get().openCapstone());

	cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

	auto insn = cs_malloc(cs);

	uint64_t address = reinterpret_cast<uint64_t>(m_trampoline);
	uint8_t const* code = reinterpret_cast<uint8_t const*>(m_trampoline);
	size_t size = 32;

	auto difference = reinterpret_cast<uint64_t>(m_trampoline) - reinterpret_cast<uint64_t>(m_address);

	auto targetAddress = address + target;

	while(cs_disasm_iter(cs, &code, &size, &address, insn)) {
		auto detail = insn->detail;

		if (detail->x86.encoding.disp_offset > 0) {
			if (detail->x86.encoding.disp_size == sizeof(int)) {
				int displaced = detail->x86.disp - difference;

				std::memcpy(
					reinterpret_cast<void*>(insn->address + detail->x86.encoding.disp_offset),
					&displaced, sizeof(int)
				);
			}
			else {
				return Err("Not supported, displacement didn't work");
			}
		}

		if (address >= targetAddress) break;
	}

	cs_free(insn, 1);

	return Ok(address - reinterpret_cast<uint64_t>(m_trampoline));
}

std::string X86Generator::intervenerString() {
	std::ostringstream out;
	out << "jmp _handler" << m_address;
	return out.str();
}

std::string X86Generator::trampolineString(size_t offset) {
	std::ostringstream out;
	out << "jmp _address" << m_address << "_" << offset; 
	return out.str();
}

#endif