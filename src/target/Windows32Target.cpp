#include "Windows32Target.hpp"

#include <Platform.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_WINDOWS)

#if defined(TULIP_HOOK_X86)

Target& Target::get() {
	static Windows32Target ret;
	return ret;
}

#endif

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "../generator/X86Generator.hpp"
#include "../Pool.hpp"
#include "../Handler.hpp"
#include "../Wrapper.hpp"

PVOID __declspec(dllexport) GeodeFunctionTableAccess64(HANDLE hProcess, DWORD64 AddrBase) {
	auto const pc = reinterpret_cast<void*>(AddrBase);
	auto const function = Target::get().getRegisteredFunction(pc);
	if (function) {
		Target::get().log([&]() {
			std::stringstream ss;
			ss << "Control PC: " << std::hex << AddrBase
				<< " Function Begin: " << function->m_address
				<< " Function End: " << function->m_endAddress;
			return ss.str();
		});
		return function->m_runtimeInfo;
	}
	return nullptr;
}

geode::Result<> Windows32Target::allocatePage() {
	m_allocatedPage = VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

	if (!m_allocatedPage) {
		return geode::Err("Unable to allocate memory: " + std::to_string(GetLastError()));
	}

	m_currentOffset = 0;
	m_remainingOffset = 0x10000;

	return geode::Ok();
}

geode::Result<uint32_t> Windows32Target::getProtection(void* address) {
	MEMORY_BASIC_INFORMATION information;

	if (!VirtualQuery(address, &information, sizeof(MEMORY_BASIC_INFORMATION))) {
		return geode::Err("Unable to query memory protection information");
	}

	return geode::Ok(information.Protect);
}

geode::Result<> Windows32Target::protectMemory(void* address, size_t size, uint32_t protection) {
	DWORD oldProtection;

	if (!VirtualProtect(address, size, protection, &oldProtection)) {
		return geode::Err("Unable to apply memory protection");
	}

	return geode::Ok();
}

geode::Result<> Windows32Target::rawWriteMemory(void* destination, void const* source, size_t size) {
	std::memcpy(destination, source, size);

	return geode::Ok();
}

uint32_t Windows32Target::getWritableProtection() {
	return PAGE_READWRITE;
}

geode::Result<csh> Windows32Target::openCapstone() {
	cs_err status;

	status = cs_open(CS_ARCH_X86, CS_MODE_32, &m_capstone);
	if (status != CS_ERR_OK) {
		return geode::Err("Couldn't open capstone");
	}

	return geode::Ok(m_capstone);
}

std::unique_ptr<BaseGenerator> Windows32Target::getGenerator() {
	return std::make_unique<X86Generator>();
}

std::shared_ptr<CallingConvention> Windows32Target::createConvention(TulipConvention convention) noexcept {
	switch (convention) {
		case TulipConvention::Cdecl: return CdeclConvention::create();
		case TulipConvention::Thiscall: return ThiscallConvention::create();
		case TulipConvention::Fastcall: return FastcallConvention::create();
		case TulipConvention::Optcall: return OptcallConvention::create();
		case TulipConvention::Membercall: return MembercallConvention::create();
		case TulipConvention::Stdcall: return StdcallConvention::create();
		default: return CdeclConvention::create();
	}
}

#endif