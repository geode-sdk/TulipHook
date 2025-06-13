#include "Windows64Target.hpp"

#include <memory>
#include <Platform.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_WINDOWS) && defined(TULIP_HOOK_X64)

#include "../Pool.hpp"
#include "../Handler.hpp"
#include "../Wrapper.hpp"
#include <Windows.h>
#include <sstream>

Target& Target::get() {
	static Windows64Target ret;
	return ret;
}

geode::Result<> Windows64Target::allocatePage() {
	m_allocatedPage = VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

	if (!m_allocatedPage) {
		return geode::Err("Unable to allocate memory: " + std::to_string(GetLastError()));
	}

	m_currentOffset = 0;
	m_remainingOffset = 0x10000;

	RtlInstallFunctionTableCallback(
		reinterpret_cast<DWORD64>(m_allocatedPage) | 0x3,
		reinterpret_cast<DWORD64>(m_allocatedPage),
		0x10000,
		+[](DWORD64 controlPc, PVOID context) -> PRUNTIME_FUNCTION {
			for (auto& [handle, handler] : Pool::get().m_handlers) {
				auto handlerBegin = reinterpret_cast<uintptr_t>(handler->m_handler);
				auto handlerEnd = handlerBegin + handler->m_handlerSize;

				auto tramplineBegin = reinterpret_cast<uintptr_t>(handler->m_trampoline);
				auto tramplineEnd = tramplineBegin + handler->m_trampolineSize;

				if (controlPc >= handlerBegin && controlPc < handlerEnd) {
					// std::stringstream ss;
					// ss << "Control PC: " << std::hex << controlPc << " Handler Begin: " << handlerBegin << " Handler End: " << handlerEnd;
					// MessageBoxA(nullptr, ss.str().c_str(), "Error Loading Geode", MB_ICONERROR);
					return reinterpret_cast<PRUNTIME_FUNCTION>(handlerEnd);
				}

				if (controlPc >= tramplineBegin && controlPc < tramplineEnd) {
					// std::stringstream ss;
					// ss << "Control PC: " << std::hex << controlPc << " Trampline Begin: " << tramplineBegin << " Trampline End: " << tramplineEnd;
					// MessageBoxA(nullptr, ss.str().c_str(), "Error Loading Geode", MB_ICONERROR);
					return reinterpret_cast<PRUNTIME_FUNCTION>(tramplineEnd);
				}
			}

			for (auto& [handle, wrapper] : Wrapper::get().m_wrappers) {
				auto wrapperBegin = reinterpret_cast<uintptr_t>(wrapper.m_address);
				auto wrapperEnd = wrapperBegin + wrapper.m_size;

				if (controlPc >= wrapperBegin && controlPc < wrapperEnd) {
					// std::stringstream ss;
					// ss << "Control PC: " << std::hex << controlPc << " Wrapper Begin: " << wrapperBegin << " Wrapper End: " << wrapperEnd;
					// MessageBoxA(nullptr, ss.str().c_str(), "Error Loading Geode", MB_ICONERROR);
					return reinterpret_cast<PRUNTIME_FUNCTION>(wrapperEnd);
				}
			}

			return nullptr;
		},
		nullptr,
		nullptr
	);

	return geode::Ok();
}

geode::Result<csh> Windows64Target::openCapstone() {
	cs_err status;

	status = cs_open(CS_ARCH_X86, CS_MODE_64, &m_capstone);
	if (status != CS_ERR_OK) {
		return geode::Err("Couldn't open capstone");
	}

	return geode::Ok(m_capstone);
}

std::unique_ptr<BaseGenerator> Windows64Target::getGenerator() {
	return std::make_unique<X64Generator>();
}

#endif