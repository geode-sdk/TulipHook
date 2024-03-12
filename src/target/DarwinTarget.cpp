#include "DarwinTarget.hpp"

#include <Platform.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_DARWIN)

#include <mach/mach.h>
#include <mach/mach_init.h> /* mach_task_self()     */
#include <mach/mach_port.h>
#include <mach/task.h>
#include <sys/mman.h>

#if !TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
// use the newer mach functions when available
#define HAS_MACH_VM 1
#include <mach/mach_vm.h> /* mach_vm_*            */

using vm_address = mach_vm_address_t;
using vm_size = mach_vm_size_t;
#else
using vm_address = vm_address_t;
using vm_size = vm_size_t;
#endif

Result<> DarwinTarget::allocatePage() {
	auto const protection = PROT_READ | PROT_WRITE;
	auto const flags = MAP_PRIVATE | MAP_ANONYMOUS;

	auto ret = mmap(nullptr, PAGE_MAX_SIZE, protection, flags, -1, 0);
	if (ret == MAP_FAILED) {
		return Err("Couldn't allocate page");
	}

	m_allocatedPage = reinterpret_cast<void*>(ret);
	m_currentOffset = 0;
	m_remainingOffset = PAGE_MAX_SIZE;

	return Ok();
}

Result<uint32_t> DarwinTarget::getProtection(void* address) {
#if defined(HAS_MACH_VM)
	// these functions take slightly differently sized types
	auto& vm_region_f = mach_vm_region;
#else
	auto& vm_region_f = vm_region_64;
#endif

	kern_return_t status;
	vm_size vmsize;
	auto vmaddress = reinterpret_cast<vm_address>(address);
	vm_region_basic_info_data_t info;
	mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;
	mach_port_t object;

	status = vm_region_f(
		mach_task_self(),
		&vmaddress,
		&vmsize,
		VM_REGION_BASIC_INFO_64,
		reinterpret_cast<vm_region_info_t>(&info),
		&infoCount,
		&object
	);

	if (status != KERN_SUCCESS) {
		return Err("Couldn't get protection");
	}

	return Ok(info.protection);
}

Result<> DarwinTarget::protectMemory(void* address, size_t size, uint32_t protection) {
#if defined(HAS_MACH_VM)
	auto& vm_region_f = mach_vm_protect;
#else
	auto& vm_region_f = vm_protect;
#endif

	kern_return_t status;

	status = vm_region_f(mach_task_self(), reinterpret_cast<vm_address>(address), size, false, protection);

	if (status != KERN_SUCCESS) {
		return Err("Couldn't protect memory");
	}
	return Ok();
}

Result<> DarwinTarget::rawWriteMemory(void* destination, void const* source, size_t size) {
#if defined(HAS_MACH_VM)
	auto& vm_region_f = mach_vm_write;
#else
	auto& vm_region_f = vm_write;
#endif

	kern_return_t status;

	status = vm_write(
		mach_task_self(),
		reinterpret_cast<vm_address>(destination),
		reinterpret_cast<vm_offset_t>(source),
		static_cast<mach_msg_type_number_t>(size)
	);

	if (status != KERN_SUCCESS) {
		return Err("Couldn't write memory");
	}
	return Ok();
}

uint32_t DarwinTarget::getMaxProtection() {
#if defined(TULIP_NO_WX)
	return VM_PROT_COPY | VM_PROT_READ | VM_PROT_WRITE;
#else
	return VM_PROT_COPY | VM_PROT_ALL;
#endif
}

Result<> DarwinTarget::toggleWXStatus(void* address, size_t size, bool executable) {
	if (executable) {
		return this->protectMemory(address, size, VM_PROT_READ | VM_PROT_EXECUTE);
	} else {
		return this->protectMemory(address, size, VM_PROT_COPY | VM_PROT_READ | VM_PROT_WRITE);
	}
}

#endif