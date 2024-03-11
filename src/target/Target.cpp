#include "Target.hpp"

using namespace tulip::hook;

Result<void*> Target::allocateArea(size_t size) {
	if (m_remainingOffset < size) {
		TULIP_HOOK_UNWRAP(this->allocatePage());
	}

	auto ret = reinterpret_cast<size_t>(m_allocatedPage) + m_currentOffset;

	m_remainingOffset -= size;
	m_currentOffset += size;

	return Ok(reinterpret_cast<void*>(ret));
}

Result<> Target::writeMemory(void* destination, void const* source, size_t size) {
	TULIP_HOOK_UNWRAP_INTO(auto oldProtection, this->getProtection(destination));

#if defined(TULIP_NO_WX)
	// with no wx pages, we run into the risk of accidentally marking our code as rw
	// (this causes a crash in the result destructor, which is not very good)

	auto r1 = this->protectMemory(destination, size, this->getMaxProtection());
	auto r2 = this->rawWriteMemory(destination, source, size);
	auto r3 = this->protectMemory(destination, size, oldProtection);

	// permissions restored, it's safe to do result stuff now
	if (r1.isErr() || r2.isErr() || r3.isErr()) {
		// return the first error
		return Err(r1.errorOr(r2.errorOr(r3.unwrapErr())));
	}
#else
	TULIP_HOOK_UNWRAP(this->protectMemory(destination, size, this->getMaxProtection()));
	TULIP_HOOK_UNWRAP(this->rawWriteMemory(destination, source, size));
	TULIP_HOOK_UNWRAP(this->protectMemory(destination, size, oldProtection));
#endif

	return Ok();
}

void Target::closeCapstone() {
#if defined(TULIP_HOOK_X86) || defined(TULIP_HOOK_X64)
	cs_close(&m_capstone);
#endif
	m_capstone = 0;
}

csh Target::getCapstone() {
	return m_capstone;
}

void* Target::getRealPtr(void* ptr) {
	return ptr;
}

void* Target::getRealPtrAs(void* ptr, void* lookup) {
	return ptr;
}
