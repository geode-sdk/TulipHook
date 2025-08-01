#include "Target.hpp"

using namespace tulip::hook;

geode::Result<void*> Target::allocateArea(size_t size) {
	if (m_remainingOffset < size) {
		GEODE_UNWRAP(this->allocatePage());
	}

	auto ret = reinterpret_cast<uintptr_t>(m_allocatedPage) + m_currentOffset;

	m_remainingOffset -= size;
	m_currentOffset += size;

	return geode::Ok(reinterpret_cast<void*>(ret));
}

geode::Result<void*> Target::peekArea() {
	if (m_remainingOffset == 0) {
		GEODE_UNWRAP(this->allocatePage());
	}

	auto ret = reinterpret_cast<uintptr_t>(m_allocatedPage) + m_currentOffset;

	return geode::Ok(reinterpret_cast<void*>(ret));	
}

geode::Result<> Target::writeMemory(void* destination, void const* source, size_t size) {
	GEODE_UNWRAP_INTO(auto oldProtection, this->getProtection(destination));
	
	GEODE_UNWRAP(this->protectMemory(destination, size, this->getWritableProtection()));

	GEODE_UNWRAP(this->rawWriteMemory(destination, source, size));

	if (oldProtection != this->getWritableProtection()) {
		// restore old protection
		GEODE_UNWRAP(this->protectMemory(destination, size, oldProtection));
	}
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

int64_t Target::getRealPtr(void* ptr) {
	return (int64_t)ptr;
}

int64_t Target::getRealPtrAs(void* ptr, void* lookup) {
	return (int64_t)ptr;
}

void Target::registerLogCallback(std::function<void(std::string_view)> callback) {
	m_logCallback = std::move(callback);
}

void Target::log(std::function<std::string()> callback) {
	if (m_logCallback) {
		m_logCallback(callback());
	}
}

void Target::registerFunction(void* address, size_t size, void* runtimeInfo) {
	void* endAddress = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(address) + size);
	m_registeredFunctions[endAddress] = { address, endAddress, runtimeInfo };
}

std::optional<RegisteredFunction> Target::getRegisteredFunction(void* pointer) {
	auto it = m_registeredFunctions.upper_bound(pointer);
	if (it != m_registeredFunctions.end() && it->second.m_address <= pointer && pointer < it->second.m_endAddress) {
		return it->second;
	}
	return std::nullopt;
}