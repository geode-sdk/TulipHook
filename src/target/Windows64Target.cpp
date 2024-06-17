#include "Windows64Target.hpp"

#include <memory>
#include <Platform.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_WINDOWS) && defined(TULIP_HOOK_X64)

#include <Windows.h>
#include "../Pool.hpp"
#include "../Handler.hpp"
#include "../Wrapper.hpp"

Target& Target::get() {
	static Windows64Target ret;
	return ret;
}

Result<> Windows64Target::allocatePage() {
	m_allocatedPage = VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

	if (!m_allocatedPage) {
		return Err("Unable to allocate memory: " + std::to_string(GetLastError()));
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
					return reinterpret_cast<PRUNTIME_FUNCTION>(handlerEnd);
				}

				if (controlPc >= tramplineBegin && controlPc < tramplineEnd) {
					return reinterpret_cast<PRUNTIME_FUNCTION>(tramplineEnd);
				}
			}

			for (auto& [handle, wrapper] : Wrapper::get().m_wrappers) {
				auto wrapperBegin = reinterpret_cast<uintptr_t>(wrapper.m_address);
				auto wrapperEnd = wrapperBegin + wrapper.m_size;

				if (controlPc >= wrapperBegin && controlPc < wrapperEnd) {
					return reinterpret_cast<PRUNTIME_FUNCTION>(wrapperEnd);
				}
			}

			return nullptr;
		},
		nullptr,
		nullptr
	);

	return Ok();
}

Result<csh> Windows64Target::openCapstone() {
	cs_err status;

	status = cs_open(CS_ARCH_X86, CS_MODE_64, &m_capstone);
	if (status != CS_ERR_OK) {
		return Err("Couldn't open capstone");
	}

	return Ok(m_capstone);
}

std::unique_ptr<HandlerGenerator> Windows64Target::getHandlerGenerator(
	void* address, void* trampoline, void* handler, void* content, HandlerMetadata const& metadata
) {
	return std::make_unique<X64HandlerGenerator>(address, trampoline, handler, content, metadata);
}

std::unique_ptr<WrapperGenerator> Windows64Target::getWrapperGenerator(void* address, WrapperMetadata const& metadata) {
	return std::make_unique<X64WrapperGenerator>(address, metadata);
}

#endif