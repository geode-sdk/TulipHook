#include "Target.hpp"

using namespace tulip::hook;

void* Target::allocateArea(size_t size) {
	if (m_remainingOffset < size) {
		this->allocatePage();
	}

	auto ret = reinterpret_cast<size_t>(m_allocatedPage) + m_currentOffset;

	m_remainingOffset -= size;
	m_currentOffset += size;

	return reinterpret_cast<void*>(ret);
}

void Target::writeMemory(void* destination, void* source, size_t size) {
	auto oldProtection = this->getProtection(destination);

	this->protectMemory(destination, size, this->getMaxProtection());

	this->rawWriteMemory(destination, source, size);

	this->protectMemory(destination, size, oldProtection);
}

void Target::closeKeystone(ks_engine* engine) {
	ks_close(m_keystone);

	m_keystone = nullptr;
}
ks_engine* Target::getKeystone() {
	return m_keystone;
}

void Target::closeCapstone(csh engine) {
	cs_close(&m_capstone);

	m_capstone = 0;
}
csh Target::getCapstone() {
	return m_capstone;
}