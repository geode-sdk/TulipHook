#include "Windows64Target.hpp"

#include <memory>
#include <Platform.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_WINDOWS) && defined(TULIP_HOOK_X64)

#include "../generator/X64Generator.hpp"
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
			auto const pc = reinterpret_cast<void*>(controlPc);
			auto const function = Target::get().getRegisteredFunction(pc);
			if (function) {
				Target::get().log([&]() {
					std::stringstream ss;
					ss << "Control PC: " << std::hex << controlPc
						<< " Function Begin: " << function->m_address
						<< " Function End: " << function->m_endAddress;
					return ss.str();
				});
				return static_cast<PRUNTIME_FUNCTION>(function->m_runtimeInfo);
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

std::shared_ptr<CallingConvention> Windows64Target::createConvention(TulipConvention convention) noexcept {
	switch (convention) {
		case TulipConvention::Thiscall: return Thiscall64Convention::create();
		default: return Windows64Convention::create();
	}
}

#endif