#include "PosixX64Target.hpp"

#include <Platform.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_POSIX) && defined(TULIP_HOOK_X64)

#include "../generator/X64Generator.hpp"

Target& Target::get() {
	static PosixX64Target ret;
	return ret;
}

geode::Result<csh> PosixX64Target::openCapstone() {
	cs_err status;

	status = cs_open(CS_ARCH_X86, CS_MODE_64, &m_capstone);
	if (status != CS_ERR_OK) {
		return geode::Err("Couldn't open capstone");
	}

	return geode::Ok(m_capstone);
}

std::unique_ptr<BaseGenerator> PosixX64Target::getGenerator() {
	return std::make_unique<X64Generator>();
}

std::shared_ptr<CallingConvention> PosixX64Target::createConvention(TulipConvention convention) noexcept {
	return SystemVConvention::create();
}

#endif