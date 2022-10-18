#include "WindowsTarget.hpp"
#include <Platform.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_WINDOWS)

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

void WindowsTarget::allocatePage() {
	m_allocatedPage = VirtualAlloc(
		nullptr, 0x4000,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
	);

	m_currentOffset = 0;
	m_remainingOffset = 0x4000;
}

uint32_t WindowsTarget::getProtection(void* address) {
	MEMORY_BASIC_INFORMATION information;
	VirtualQuery(address, &information, sizeof(MEMORY_BASIC_INFORMATION));

	return information.Protect;
}

void WindowsTarget::protectMemory(void* address, size_t size, uint32_t protection) {
	uint32_t oldProtection;

	VirtualProtect(address, size, protection, &oldProtection);
}

void WindowsTarget::rawWriteMemory(void* destination, void* source, size_t size) {
	WriteProcessMemory(GetCurrentProcess(), destination, source, size, nullptr);
}

uint32_t WindowsTarget::getMaxProtection() {
	return PAGE_EXECUTE_READWRITE;
}

WindowsTarget& WindowsTarget::get() {
	static WindowsTarget ret;
	return ret;
}

ks_engine* WindowsTarget::openKeystone() {
	ks_err status;

	status = ks_open(KS_ARCH_X86, KS_MODE_32, &m_keystone);
	if (status != KS_ERR_OK) {
		throw std::runtime_error("TulipHook - couldn't open keystone");
	}

	return m_keystone;
}

csh WindowsTarget::openCapstone() {
	cs_err status;

	status = cs_open(CS_ARCH_X86, CS_MODE_32, &m_capstone);
	if (status != CS_ERR_OK) {
		throw std::runtime_error("TulipHook - couldn't open capstone");
	}

	return m_capstone;
}



#endif