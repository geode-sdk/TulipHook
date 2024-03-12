#include "DarwinTarget.hpp"

#include <Platform.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_DARWIN)

#include <mach/mach.h>
#include <mach/mach_init.h> /* mach_task_self()     */
#include <mach/mach_port.h>
#include <mach/mach_vm.h> /* mach_vm_*            */
#include <mach/task.h>

Result<> DarwinTarget::allocatePage() {
	kern_return_t status;
	mach_vm_address_t ret;

	status = mach_vm_allocate(mach_task_self(), &ret, PAGE_MAX_SIZE, VM_FLAGS_ANYWHERE);

	if (status != KERN_SUCCESS) {
		return Err("Couldn't allocate page");
	}

	m_allocatedPage = reinterpret_cast<void*>(ret);
	m_currentOffset = 0;
	m_remainingOffset = PAGE_MAX_SIZE;

	return this->protectMemory(m_allocatedPage, m_remainingOffset, VM_PROT_COPY | VM_PROT_READ | VM_PROT_WRITE);
}

Result<uint32_t> DarwinTarget::getProtection(void* address) {
	kern_return_t status;
	mach_vm_size_t vmsize;
	mach_vm_address_t vmaddress = reinterpret_cast<mach_vm_address_t>(address);
	vm_region_basic_info_data_t info;
	mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;
	mach_port_t object;

	status = mach_vm_region(
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
	kern_return_t status;

	status = mach_vm_protect(mach_task_self(), reinterpret_cast<mach_vm_address_t>(address), size, false, protection);

	if (status != KERN_SUCCESS) {
		return Err("Couldn't protect memory");
	}
	return Ok();
}

Result<> DarwinTarget::rawWriteMemory(void* destination, void const* source, size_t size) {
	kern_return_t status;

	status = mach_vm_write(
		mach_task_self(),
		reinterpret_cast<mach_vm_address_t>(destination),
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