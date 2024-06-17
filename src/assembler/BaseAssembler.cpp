#include "BaseAssembler.hpp"

using namespace tulip::hook;

BaseAssembler::BaseAssembler(int64_t baseAddress) :
	m_baseAddress(baseAddress) {}

BaseAssembler::~BaseAssembler() {}

int8_t BaseAssembler::read8(int64_t address) const {
	return m_buffer[address - m_baseAddress];
}

int16_t BaseAssembler::read16(int64_t address) const {
	const auto lo = read8(address);
	const auto hi = read8(address + 1);
	return ((static_cast<int16_t>(hi) << 8) | lo);
}

int32_t BaseAssembler::read32(int64_t address) const {
	const auto lo = read16(address);
	const auto hi = read16(address + 2);
	return ((static_cast<int32_t>(hi) << 16) | lo);
}

int64_t BaseAssembler::read64(int64_t address) const {
	const auto lo = read32(address);
	const auto hi = read32(address + 4);
	return ((static_cast<int64_t>(hi) << 32) | lo);
}

void BaseAssembler::write8(int8_t value) {
	m_buffer.push_back(value);
}

void BaseAssembler::write16(int16_t value) {
	write8(value & 0xFF);
	write8((value >> 8) & 0xFF);
}

void BaseAssembler::write32(int32_t value) {
	write16(value & 0xFFFF);
	write16((value >> 16) & 0xFFFF);
}

void BaseAssembler::write64(int64_t value) {
	write32(value & 0xFFFFFFFF);
	write32((value >> 32) & 0xFFFFFFFF);
}

int64_t BaseAssembler::currentAddress() const {
	return m_baseAddress + m_buffer.size();
}

std::vector<uint8_t> const& BaseAssembler::buffer() const {
	return m_buffer;
}

void BaseAssembler::rewrite8(int64_t address, int8_t value) {
	m_buffer[address - m_baseAddress] = value;
}

void BaseAssembler::rewrite16(int64_t address, int16_t value) {
	rewrite8(address, value & 0xFF);
	rewrite8(address + 1, (value >> 8) & 0xFF);
}

void BaseAssembler::rewrite32(int64_t address, int32_t value) {
	rewrite16(address, value & 0xFFFF);
	rewrite16(address + 2, (value >> 16) & 0xFFFF);
}

void BaseAssembler::rewrite64(int64_t address, int64_t value) {
	rewrite32(address, value & 0xFFFFFFFF);
	rewrite32(address + 4, (value >> 32) & 0xFFFFFFFF);
}

void BaseAssembler::label(std::string const& name) {
	m_labels[name] = this->currentAddress();
}

void* BaseAssembler::getLabel(std::string const& name) const {
	if (m_labels.find(name) == m_labels.end()) {
		return nullptr;
	}
	return reinterpret_cast<void*>(m_labels.at(name));
}

void BaseAssembler::updateLabels() {}