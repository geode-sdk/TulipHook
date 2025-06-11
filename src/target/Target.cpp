#include "Target.hpp"

using namespace tulip::hook;

geode::Result<void*> Target::allocateArea(size_t size) {
	if (m_remainingOffset < size) {
		GEODE_UNWRAP(this->allocatePage());
	}

	auto ret = reinterpret_cast<size_t>(m_allocatedPage) + m_currentOffset;

	m_remainingOffset -= size;
	m_currentOffset += size;

	return geode::Ok(reinterpret_cast<void*>(ret));
}

geode::Result<> Target::writeMemory(void* destination, void const* source, size_t size) {
	GEODE_UNWRAP(this->rawWriteMemory(destination, source, size));

	return geode::Ok();
}

geode::Result<> Target::finalizePage() {
	return geode::Ok();
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
