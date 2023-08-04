#include "X86Assembler.hpp"

using namespace tulip::hook;

uint8_t regv(X86Register reg) {
	return static_cast<uint8_t>(reg);
}

uint8_t regv(X86Pointer ptr) {
	return regv(ptr.m_register);
}

uint8_t regx(X86Register reg) {
	return regv(reg) - 0x80;
}

bool espcheck(X86Pointer ptr) {
	return regv(ptr) == 0x4;
}

X86Assembler::X86Assembler(uint64_t baseAddress) :
	BaseAssembler(baseAddress) {}

X86Assembler::~X86Assembler() {}

void X86Assembler::label32(std::string const& name) {
	m_labelUpdates.push_back({this->currentAddress(), name, 4});
	this->write32(0);
}

void X86Assembler::updateLabels() {
	for (auto const& update : m_labelUpdates) {
		this->rewrite32(update.m_address, m_labels[update.m_name] - update.m_address - 4);
	}
}

void X86Assembler::nop() {
	this->write8(0x90);
}

void X86Assembler::add(X86Register reg, uint32_t value) {
	this->write8(0x81);
	this->write8(0xC0 | regv(reg));
	this->write32(value);
}

void X86Assembler::sub(X86Register reg, uint32_t value) {
	this->write8(0x81);
	this->write8(0xE8 | regv(reg));
	this->write32(value);
}

void X86Assembler::push(X86Register reg) {
	this->write8(0x50 | regv(reg));
}

void X86Assembler::push(X86Pointer reg) {
	this->write8(0xFF);
	this->write8(0xB0 | regv(reg));
	if (espcheck(reg)) {
		this->write8(0x24);
	}
	this->write32(reg.m_offset);
}

void X86Assembler::pop(X86Register reg) {
	this->write8(0x58 | regv(reg));
}

void X86Assembler::jmp(X86Register reg) {
	this->write8(0xFF);
	this->write8(0xE0 | regv(reg));
}

void X86Assembler::jmp(uint64_t address) {
	this->write8(0xE9);
	this->write32(address - this->currentAddress() - 4);
}

void X86Assembler::call(X86Register reg) {
	this->write8(0xFF);
	this->write8(0xD0 | regv(reg));
}

void X86Assembler::movsd(X86Register reg, X86Pointer ptr) {
	this->write8(0xF2);
	this->write8(0x0F);
	this->write8(0x10);
	this->write8(0x80 | regv(ptr) | regx(reg) * 8);
	if (espcheck(ptr)) {
		this->write8(0x24);
	}
	this->write32(ptr.m_offset);
}

void X86Assembler::movsd(X86Pointer ptr, X86Register reg) {
	this->write8(0xF2);
	this->write8(0x0F);
	this->write8(0x11);
	this->write8(0x80 | regv(ptr) | regx(reg) * 8);
	if (espcheck(ptr)) {
		this->write8(0x24);
	}
	this->write32(ptr.m_offset);
}

void X86Assembler::mov(X86Register reg, uint32_t value) {
	this->write8(0xB8 | regv(reg));
	this->write32(value);
}

void X86Assembler::mov(X86Register reg, X86Pointer ptr) {
	this->write8(0x8B);
	this->write8(0x80 | regv(ptr) | regx(reg) * 8);
	if (espcheck(ptr)) {
		this->write8(0x24);
	}
	this->write32(ptr.m_offset);
}

void X86Assembler::mov(X86Pointer ptr, X86Register reg) {
	this->write8(0x89);
	this->write8(0x80 | regv(ptr) | regx(reg) * 8);
	if (espcheck(ptr)) {
		this->write8(0x24);
	}
	this->write32(ptr.m_offset);
}

void X86Assembler::mov(X86Register reg, X86Register reg2) {
	this->write8(0x89);
	this->write8(0xC0 | regv(reg) | regx(reg2) * 8);
}

void X86Assembler::mov(X86Register reg, std::string const& label) {
	this->write8(0x8b);
	this->write8(0x05 | regv(reg) * 8);
	this->label32(label);
}