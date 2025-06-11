#include "iOSTarget.hpp"

#include <Platform.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_IOS) && defined(TULIP_HOOK_ARMV8)

#include <mach/mach.h>
#include <mach/mach_init.h> /* mach_task_self()     */
#include <mach/mach_port.h>
#include <mach/vm_map.h> /* vm_allocate()        */
#include <mach/task.h>

#include "../Pool.hpp"

Target& Target::get() {
	static iOSTarget ret;
	return ret;
}

geode::Result<> iOSTarget::allocatePage() {
	kern_return_t status;
	vm_address_t ret;

	status = vm_allocate(mach_task_self(), &ret, static_cast<vm_size_t>(PAGE_MAX_SIZE), VM_FLAGS_ANYWHERE);

	if (status != KERN_SUCCESS) {
		return geode::Err("Couldn't allocate page (iOS)");
	}

	m_allocatedPage = reinterpret_cast<void*>(ret);
	m_currentOffset = 0;
	m_remainingOffset = PAGE_MAX_SIZE;

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

std::unique_ptr<HandlerGenerator> iOSTarget::getHandlerGenerator(
	void* address, void* trampoline, void* handler, void* content, HandlerMetadata const& metadata
) {
	if (Pool::get().m_runtimeInterveningDisabled) {
		return std::make_unique<PatchlessArmV8HandlerGenerator>(address, trampoline, handler, content, metadata);
	}
	return std::make_unique<ArmV8HandlerGenerator>(address, trampoline, handler, content, metadata);
}

std::unique_ptr<WrapperGenerator> iOSTarget::getWrapperGenerator(void* address, WrapperMetadata const& metadata) {
	return std::make_unique<ArmV8WrapperGenerator>(address, metadata);
}

uint32_t iOSTarget::getWritableProtection() {
	return VM_PROT_COPY | VM_PROT_READ | VM_PROT_WRITE;
}

// geode::Result<> iOSTarget::writeMemory(void* destination, void const* source, size_t size) {
// 	if (!Pool::get().m_runtimeInterveningDisabled) {
// 		return DarwinTarget::writeMemory(destination, source, size);
// 	}
// 	GEODE_UNWRAP(this->rawWriteMemory(destination, source, size).mapErr(
// 		[&](auto&& err) {
// 			return "Couldn't write memory (iOS): " + std::move(err) + 
// 			       " (destination: " + std::to_string(reinterpret_cast<uintptr_t>(destination)) +
// 			       ", source: " + std::to_string(reinterpret_cast<uintptr_t>(source)) +
// 			       ", size: " + std::to_string(size) + ") - " + 
// 				   " m_allocatedPage: " + std::to_string(reinterpret_cast<uintptr_t>(m_allocatedPage)) +
// 			       ", m_currentOffset: " + std::to_string(m_currentOffset) + 
// 			       ", m_remainingOffset: " + std::to_string(m_remainingOffset);
// 		}
// 	));

// 	return geode::Ok();
// }

geode::Result<> iOSTarget::finalizePage() {
	GEODE_UNWRAP(this->protectMemory(m_allocatedPage, PAGE_MAX_SIZE, VM_PROT_READ | VM_PROT_EXECUTE).mapErr(
		[](auto&& err) {
			return "Couldn't finalize page (iOS): " + std::move(err);
		}
	));

	m_remainingOffset = 0;
	return geode::Ok();
}

#endif