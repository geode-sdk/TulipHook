#include "Target.hpp"
#include <Platform.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_MACOS)

#include <mach/mach.h>
#include <mach/task.h>
#include <mach/mach_port.h>
#include <mach/mach_vm.h>       /* mach_vm_*            */
#include <mach/mach_init.h>     /* mach_task_self()     */

class Target::TargetImpl {
public:

	void* m_allocatedPage = nullptr;
	size_t m_currentOffset = 0;
	size_t m_remainingOffset = 0;

	ks_engine* m_keystone = nullptr;
	csh m_capstone = 0;

	void allocatePage() {
		kern_return_t status;
		mach_vm_address_t ret;

		status = mach_vm_allocate(
			mach_task_self(), 
			&ret, 
			static_cast<mach_vm_size_t>(0x1000), 
			VM_FLAGS_ANYWHERE
		);

		if (status != KERN_SUCCESS) {
			throw std::runtime_error("TulipHook - couldn't allocate page");
		}

		m_allocatedPage = reinterpret_cast<void*>(ret);
		m_currentOffset = 0;
		m_remainingOffset = 0x1000;

		this->protectMemory(m_allocatedPage, m_remainingOffset, VM_PROT_COPY | VM_PROT_ALL);
	}

	vm_prot_t getProtection(void* address) {
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
			throw std::runtime_error("TulipHook - couldn't get protection");
		}

		return info.protection;
	}

	void protectMemory(void* address, size_t size, vm_prot_t protection) {
		kern_return_t status;

		status = mach_vm_protect(
			mach_task_self(), 
			reinterpret_cast<mach_vm_address_t>(address), 
			size, 
			false, 
			protection
		);

    	if (status != KERN_SUCCESS) {
			throw std::runtime_error("TulipHook - couldn't protect memory");
		}
	}

	void writeMemory(void* destination, void* source, size_t size) {
		kern_return_t status;

		status = mach_vm_write(
			mach_task_self(), 
			reinterpret_cast<mach_vm_address_t>(destination), 
			reinterpret_cast<vm_offset_t>(source), 
			static_cast<mach_msg_type_number_t>(size)
		);

		if (status != KERN_SUCCESS) {
			throw std::runtime_error("TulipHook - couldn't write memory");
		}
	}
};

Target::Target() : m_impl(new TargetImpl()) {

}

Target& Target::get() {
	static Target ret;
	return ret;
}

void* Target::allocateArea(size_t size) {
	if (m_impl->m_remainingOffset < size) {
		m_impl->allocatePage();
	}

	auto ret = reinterpret_cast<size_t>(m_impl->m_allocatedPage) + m_impl->m_currentOffset;

	m_impl->m_remainingOffset -= size;
	m_impl->m_currentOffset += size;

	return reinterpret_cast<void*>(ret);
}

void Target::writeMemory(void* destination, void* source, size_t size) {
	auto oldProtection = m_impl->getProtection(destination);

	m_impl->protectMemory(destination, size, VM_PROT_COPY | VM_PROT_ALL);

	m_impl->writeMemory(destination, source, size);

	m_impl->protectMemory(destination, size, oldProtection);
}

ks_engine* Target::openKeystone() {
	ks_err status;

	status = ks_open(KS_ARCH_X86, KS_MODE_64, &m_impl->m_keystone);
	if (status != KS_ERR_OK) {
		throw std::runtime_error("TulipHook - couldn't open keystone");
	}

	return m_impl->m_keystone;
}
void Target::closeKeystone(ks_engine* engine) {
	ks_close(m_impl->m_keystone);

	m_impl->m_keystone = nullptr;
}
ks_engine* Target::getKeystone() {
	return m_impl->m_keystone;
}

csh Target::openCapstone() {
	cs_err status;

	status = cs_open(CS_ARCH_X86, CS_MODE_64, &m_impl->m_capstone);
	if (status != CS_ERR_OK) {
		throw std::runtime_error("TulipHook - couldn't open capstone");
	}

	return m_impl->m_capstone;
}
void Target::closeCapstone(csh engine) {
	cs_close(&m_impl->m_capstone);

	m_impl->m_capstone = 0;
}
csh Target::getCapstone() {
	return m_impl->m_capstone;
}


#endif