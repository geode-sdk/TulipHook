#include "iOSTarget.hpp"

#include <Platform.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_IOS) && defined(TULIP_HOOK_ARMV8)

#include <mach/vm_map.h> /* vm_allocate()        */

Target& Target::get() {
	static iOSTarget ret;
	return ret;
}

geode::Result<csh> iOSTarget::openCapstone() {
	// cs_err status;

	// status = cs_open(CS_ARCH_X86, CS_MODE_64, &m_capstone);
	// if (status != CS_ERR_OK) {
		return geode::Err("Couldn't open capstone");
	// }

	// return geode::Ok(m_capstone);
}

std::unique_ptr<BaseGenerator> iOSTarget::getGenerator() {
	return std::make_unique<ArmV8Generator>();
}

uint32_t iOSTarget::getWritableProtection() {
	return VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY;
}

#endif