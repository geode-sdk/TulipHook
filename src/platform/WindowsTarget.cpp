#include "WindowsTarget.hpp"
#include <Platform.hpp>

#include <stdexcept>

using namespace tulip::hook;

#if defined(TULIP_HOOK_WINDOWS)

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

Result<> WindowsTarget::allocatePage() {
	m_allocatedPage = VirtualAlloc(
		nullptr, 0x4000,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
	);

	if (!m_allocatedPage) {
		return Err("Unable to allocate memory: " + std::to_string(GetLastError()));
	}

	m_currentOffset = 0;
	m_remainingOffset = 0x4000;

	return Ok();
}

Result<uint32_t> WindowsTarget::getProtection(void* address) {
	MEMORY_BASIC_INFORMATION information;
	
	if (!VirtualQuery(address, &information, sizeof(MEMORY_BASIC_INFORMATION))) {
		return Err("Unable to query memory protection information");
	}

	return Ok(information.Protect);
}

Result<> WindowsTarget::protectMemory(void* address, size_t size, uint32_t protection) {
	DWORD oldProtection;

	if (!VirtualProtect(address, size, protection, &oldProtection)) {
		return Err("Unable to apply memory protection");
	}

	return Ok();
}

Result<> WindowsTarget::rawWriteMemory(void* destination, void* source, size_t size) {
	if (!WriteProcessMemory(GetCurrentProcess(), destination, source, size, nullptr)) {
		return Err("Unable to write to memory");
	}
	return Ok();
}

uint32_t WindowsTarget::getMaxProtection() {
	return PAGE_EXECUTE_READWRITE;
}

WindowsTarget& WindowsTarget::get() {
	static WindowsTarget ret;
	return ret;
}

Result<ks_engine*> WindowsTarget::openKeystone() {

	if (ks_open(KS_ARCH_X86, KS_MODE_32, &m_keystone) != KS_ERR_OK) {
		return Err("Couldn't open keystone");
	}

	return Ok(m_keystone);
}

Result<csh> WindowsTarget::openCapstone() {
	cs_err status;

	status = cs_open(CS_ARCH_X86, CS_MODE_32, &m_capstone);
	if (status != CS_ERR_OK) {
		return Err("Couldn't open capstone");
	}

	return Ok(m_capstone);
}



#endif