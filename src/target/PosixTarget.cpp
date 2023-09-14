#include "PosixTarget.hpp"

#include <Platform.hpp>
#include <stdexcept>

using namespace tulip::hook;

#if defined(TULIP_HOOK_POSIX)

#include <sys/mman.h>

Result<> PosixTarget::allocatePage() {
	auto const protection = PROT_READ | PROT_WRITE | PROT_EXEC;
	auto const flags = MAP_PRIVATE | MAP_ANONYMOUS;

	auto ret = mmap(nullptr, 0x4000, flags, protection, -1, 0);

	if (ret == MAP_FAILED) {
		return Err("Couldn't allocate page");
	}

	m_allocatedPage = reinterpret_cast<void*>(ret);
	m_currentOffset = 0;
	m_remainingOffset = 0x4000;

	return Ok();
}

Result<uint32_t> PosixTarget::getProtection(void* address) {
	// why
	// just why does posix not have get protection
	return Ok(this->getMaxProtection());
}

Result<> PosixTarget::protectMemory(void* address, size_t size, uint32_t protection) {
	auto status = mprotect(address, size, protection);

	if (status != 0) {
		return Err("Couldn't protect memory");
	}
	return Ok();
}

Result<> PosixTarget::rawWriteMemory(void* destination, void const* source, size_t size) {
	auto res = this->protectMemory(destination, size, this->getMaxProtection());

	if (!res) {
		return Err("Couldn't protect memory");
	}

	std::memcpy(destination, source, size);

	return Ok();
}

uint32_t PosixTarget::getMaxProtection() {
	return PROT_READ | PROT_WRITE | PROT_EXEC;
}

#endif