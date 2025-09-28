#include "iOSTarget.hpp"

#include <Platform.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_IOS) && defined(TULIP_HOOK_ARMV8)

#include <mach/vm_map.h> /* vm_allocate()        */
#include <mach/mach_init.h> /* mach_task_self()     */

// TXM (iOS 26) workaround, having the debug server do all the allocating and patching

// x0 (addr), x1 (bytes)
__attribute__((noinline,optnone,naked))
void BreakMarkJITMapping(uint64_t addr, size_t bytes) {
    asm("brk #0x69 \n"
        "ret");
}

// x0 (dest), x1 (src), x2 (bytes)
__attribute__((noinline,optnone,naked))
void BreakJITWrite(uint64_t dest, uint64_t src, size_t bytes) {
    asm("brk #0x70 \n"
        "ret");
}

Target& Target::get() {
	static iOSTarget ret;
    ret.m_useTxmJIT = getenv("TXM_JIT"); // using it here as setting it as a static const bool in source is too early
	return ret;
}

geode::Result<> iOSTarget::allocatePage() {
	kern_return_t status;
	vm_address_t ret;

	status = vm_allocate(mach_task_self(), &ret, static_cast<vm_size_t>(0x10000), VM_FLAGS_ANYWHERE);
	if (status != KERN_SUCCESS) {
		return geode::Err("Couldn't allocate page");
	}
	m_allocatedPage = reinterpret_cast<void*>(ret);
	m_currentOffset = 0;
	m_remainingOffset = 0x10000;
	this->internalProtectMemory(m_allocatedPage, 0x10000, VM_PROT_READ | VM_PROT_EXECUTE, status);
	if (status != KERN_SUCCESS) {
		return geode::Err("Couldn't protect memory as RX");
	}
	if (m_useTxmJIT) {
		BreakMarkJITMapping(ret, 0x10000);
	}
	return geode::Ok();
}
geode::Result<> iOSTarget::protectMemory(void* address, size_t size, uint32_t protection) {
	if (useTxmJIT) {
		GEODE_UNWRAP_INTO(auto currentProtection, this->getProtection(address));
		// You cant protect whats already executable
		if ((currentProtection & VM_PROT_EXECUTE) && (protection & VM_PROT_WRITE)) {
			return geode::Ok();
		}
	}
	kern_return_t status;

	this->internalProtectMemory(address, size, protection, status);
	if (status != KERN_SUCCESS) {
		return geode::Err("Couldn't protect memory: " + std::to_string(status));
	}
	return geode::Ok();
}
geode::Result<> iOSTarget::rawWriteMemory(void* destination, void const* source, size_t size) {
	kern_return_t status;
	if (m_useTxmJIT) {
		GEODE_UNWRAP_INTO(auto currentProtection, this->getProtection(destination));
		if ((currentProtection & VM_PROT_EXECUTE)) {
			BreakJITWrite(reinterpret_cast<uint64_t>(destination), reinterpret_cast<uint64_t>(source), size);
			return geode::Ok();
		}
	}
	this->internalWriteMemory(destination, source, size, status);
	if (status != KERN_SUCCESS) {
		return geode::Err("Couldn't write memory: " + std::to_string(status));
	}
	return geode::Ok();
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

std::shared_ptr<CallingConvention> iOSTarget::createConvention(TulipConvention convention) noexcept {
	return AAPCS64Convention::create();
}

#endif
