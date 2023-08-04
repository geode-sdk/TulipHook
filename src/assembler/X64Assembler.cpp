#include "X64Assembler.hpp"

using namespace tulip::hook;

uint8_t regv(X64Register reg) {
	return static_cast<uint8_t>(reg);
}

uint8_t regv(X64Pointer ptr) {
	return regv(ptr.m_register);
}

uint8_t regl(X64Register reg) {
	return regv(reg) & 0x7;
}

uint8_t regl(X64Pointer ptr) {
	return regv(ptr) & 0x7;
}

uint8_t regx(X64Register reg) {
	return regv(reg) - 0x80;
}

bool espcheck(X64Pointer ptr) {
	return regl(ptr) == 0x4;
}

bool lowerreg(X64Register reg) {
	return regv(reg) < 0x8;
}

bool lowerreg(X64Pointer ptr) {
	return regv(ptr) < 0x8;
}

uint8_t lowerv(X64Register reg, uint8_t offset) {
	return lowerreg(reg) << offset;
}

uint8_t lowerv(X64Pointer ptr, uint8_t offset) {
	return lowerreg(ptr) << offset;
}

X64Assembler::X64Assembler(uint64_t baseAddress) :
	BaseAssembler(baseAddress) {}

X64Assembler::~X64Assembler() {}

void X64Assembler::label32(std::string const& name) {
	m_labelUpdates.push_back({this->currentAddress(), name, 4});
	this->write32(0);
}

void X64Assembler::updateLabels() {
	for (auto const& update : m_labelUpdates) {
		this->rewrite32(update.m_address, m_labels[update.m_name] - update.m_address - 4);
	}
}

void X64Assembler::nop() {
	this->write8(0x90);
}

void X64Assembler::add(X64Register reg, uint32_t value) {
	this->write8(0x48 | lowerv(reg, 0));
	this->write8(0x81);
	this->write8(0xC0 | regl(reg));
	this->write32(value);
}

void X64Assembler::sub(X64Register reg, uint32_t value) {
	this->write8(0x48 | lowerv(reg, 0));
	this->write8(0x81);
	this->write8(0xE8 | regl(reg));
	this->write32(value);
}

void X64Assembler::jmp(X64Register reg) {
	this->write8(0x40 | lowerv(reg, 0));
	this->write8(0xFF);
	this->write8(0xE0 | regl(reg));
}

void X64Assembler::jmp(uint64_t address) {
	this->write8(0xE9);
	this->write32(address - this->currentAddress() - 4);
}

void X64Assembler::call(X64Register reg) {
	this->write8(0x40 | lowerv(reg, 0));
	this->write8(0xFF);
	this->write8(0xD0 | regl(reg));
}

void X64Assembler::lea(X64Register reg, std::string const& label) {
	this->write8(0x48 | lowerv(reg, 2));
	this->write8(0x8D);
	this->write8(0x05 | regl(reg) * 8);
	this->label32(label);
}

void X64Assembler::movaps(X64Register reg, X64Pointer ptr) {
	this->write8(0x40 | lowerv(ptr, 0));
	this->write8(0x0F);
	this->write8(0x28);
	this->write8(0x80 | regl(ptr) | regx(reg) * 8);
	if (espcheck(ptr)) {
		this->write8(0x24);
	}
	this->write32(ptr.m_offset);
}

void X64Assembler::movaps(X64Pointer ptr, X64Register reg) {
	this->write8(0x40 | lowerv(ptr, 0));
	this->write8(0x0F);
	this->write8(0x29);
	this->write8(0x80 | regl(ptr) | regx(reg) * 8);
	if (espcheck(ptr)) {
		this->write8(0x24);
	}
	this->write32(ptr.m_offset);
}

void X64Assembler::mov(X64Register reg, uint32_t value) {
	this->write8(0x48 | lowerv(reg, 0));
	this->write8(0xC7);
	this->write8(0xC0 | regl(reg));
	this->write32(value);
}

void X64Assembler::mov(X64Register reg, X64Pointer ptr) {
	this->write8(0x48 | lowerv(ptr, 0) | lowerv(reg, 2));
	this->write8(0x8B);
	this->write8(0x80 | regl(ptr) | regl(reg) * 8);
	if (espcheck(ptr)) {
		this->write8(0x24);
	}
	this->write32(ptr.m_offset);
}

void X64Assembler::mov(X64Pointer ptr, X64Register reg) {
	this->write8(0x48 | lowerv(ptr, 0) | lowerv(reg, 2));
	this->write8(0x89);
	this->write8(0x80 | regl(ptr) | regl(reg) * 8);
	if (espcheck(ptr)) {
		this->write8(0x24);
	}
	this->write32(ptr.m_offset);
}

void X64Assembler::mov(X64Register reg, X64Register reg2) {
	this->write8(0x48 | lowerv(reg, 0) | lowerv(reg2, 2));
	this->write8(0x89);
	this->write8(0xC0 | regl(reg) | regl(reg2) * 8);
}

void X64Assembler::mov(X64Register reg, std::string const& label) {
	this->write8(0x48 | lowerv(reg, 2));
	this->write8(0x8B);
	this->write8(0x05 | regl(reg) * 8);
	this->label32(label);
}