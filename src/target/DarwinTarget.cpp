#include "DarwinTarget.hpp"

#include <Platform.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_DARWIN)

#include <mach/mach.h>
#include <mach/mach_init.h> /* mach_task_self()     */
#include <mach/mach_port.h>
#include <mach/vm_map.h> /* vm_allocate()        */
#include <mach/task.h>

geode::Result<> DarwinTarget::allocatePage() {
	kern_return_t status;
	vm_address_t ret;

	status = vm_allocate(mach_task_self(), &ret, static_cast<vm_size_t>(0x10000), VM_FLAGS_ANYWHERE);

	if (status != KERN_SUCCESS) {
		return geode::Err("Couldn't allocate page");
	}

	m_allocatedPage = reinterpret_cast<void*>(ret);
	m_currentOffset = 0;
	m_remainingOffset = 0x10000;

	return this->protectMemory(m_allocatedPage, 0x10000, VM_PROT_READ | VM_PROT_EXECUTE);
}

geode::Result<uint32_t> DarwinTarget::getProtection(void* address) {
	kern_return_t status;
	vm_size_t vmsize;
	vm_address_t vmaddress = reinterpret_cast<vm_address_t>(address);
	vm_region_basic_info_data_t info;
	mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;
	mach_port_t object;

	status = vm_region_64(
		mach_task_self(),
		&vmaddress,
		&vmsize,
		VM_REGION_BASIC_INFO_64,
		reinterpret_cast<vm_region_info_t>(&info),
		&infoCount,
		&object
	);

	if (status != KERN_SUCCESS) {
		return geode::Err("Couldn't get protection");
	}

	return geode::Ok(info.protection);
}

void DarwinTarget::internalProtectMemory(void* address, size_t size, uint32_t protection, int& errorCode) {
	errorCode = vm_protect(
		mach_task_self(),
		reinterpret_cast<vm_address_t>(address),
		size,
		false,
		protection
	);
}
void DarwinTarget::internalWriteMemory(void* destination, void const* source, size_t size, int& errorCode) {
	errorCode = vm_write(
		mach_task_self(),
		reinterpret_cast<vm_address_t>(destination),
		reinterpret_cast<vm_offset_t>(source),
		static_cast<mach_msg_type_number_t>(size)
	);
}

geode::Result<> DarwinTarget::protectMemory(void* address, size_t size, uint32_t protection) {
	kern_return_t status;

	this->internalProtectMemory(address, size, protection, status);
	if (status != KERN_SUCCESS) {
		return geode::Err("Couldn't protect memory: " + std::to_string(status));
	}
	return geode::Ok();
}

geode::Result<> DarwinTarget::rawWriteMemory(void* destination, void const* source, size_t size) {
	kern_return_t status;

	this->internalWriteMemory(destination, source, size, status);
	if (status != KERN_SUCCESS) {
		return geode::Err("Couldn't write memory: " + std::to_string(status));
	}
	return geode::Ok();
}

uint32_t DarwinTarget::getWritableProtection() {
	return VM_PROT_COPY | VM_PROT_READ | VM_PROT_WRITE;
}

#endif