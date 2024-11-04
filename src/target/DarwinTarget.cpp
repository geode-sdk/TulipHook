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

	status = vm_allocate(mach_task_self(), &ret, static_cast<vm_size_t>(PAGE_MAX_SIZE), VM_FLAGS_ANYWHERE);

	if (status != KERN_SUCCESS) {
		return geode::Err("Couldn't allocate page");
	}

	m_allocatedPage = reinterpret_cast<void*>(ret);
	m_currentOffset = 0;
	m_remainingOffset = PAGE_MAX_SIZE;

	return this->protectMemory(m_allocatedPage, PAGE_MAX_SIZE, VM_PROT_READ | VM_PROT_EXECUTE);
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

geode::Result<> DarwinTarget::protectMemory(void* address, size_t size, uint32_t protection) {
	kern_return_t status;

	status = vm_protect(mach_task_self(), reinterpret_cast<vm_address_t>(address), size, false, protection);

	if (status != KERN_SUCCESS) {
		return geode::Err("Couldn't protect memory");
	}
	return geode::Ok();
}

geode::Result<> DarwinTarget::rawWriteMemory(void* destination, void const* source, size_t size) {
	kern_return_t status;

	status = vm_write(
		mach_task_self(),
		reinterpret_cast<vm_address_t>(destination),
		reinterpret_cast<vm_offset_t>(source),
		static_cast<mach_msg_type_number_t>(size)
	);
	if (status != KERN_SUCCESS) {
		return geode::Err("Couldn't write memory, status: " + std::to_string(status));
	}
	return geode::Ok();
}

geode::Result<> DarwinTarget::writeMemory(void* destination, void const* source, size_t size) {
	GEODE_UNWRAP_INTO(auto oldProtection, this->getProtection(destination));

	// with no wx pages, we run into the risk of accidentally marking our code as rw
	// (this causes a crash in the result destructor, which is not very good)

	auto r1 = this->protectMemory(destination, size, this->getWritableProtection());
	auto r2 = r1.isOk() ? this->rawWriteMemory(destination, source, size) : r1;
	auto r3 = r1.isOk() ? this->protectMemory(destination, size, oldProtection) : r1;

	// permissions restored, it's safe to do result stuff now
	if (r1.isErr() || r2.isErr() || r3.isErr()) {
		// return the first error
		return geode::Err(r1.errorOr(r2.errorOr(r3.unwrapErr())));
	}
	return geode::Ok();
}

uint32_t DarwinTarget::getWritableProtection() {
	return VM_PROT_COPY | VM_PROT_READ | VM_PROT_WRITE;
}

#endif