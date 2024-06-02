#include "X64Assembler.hpp"

using namespace tulip::hook;

uint8_t regv(X64Register reg) {
	return static_cast<uint8_t>(reg);
}

uint8_t regv(X64Pointer ptr) {
	return regv(ptr.reg);
}

uint8_t lowerv(X64Register reg, uint8_t offset) {
	return (regv(reg) >> 3) << offset;
}

uint8_t lowerv(X64Pointer ptr, uint8_t offset) {
	return (regv(ptr) >> 3) << offset;
}

uint8_t regIdx(X64Register reg) {
	return static_cast<uint8_t>(reg) & 0x7;
}

void rex(X64Assembler* ass, X64Register reg, X64Register reg2, bool wide) {
	auto rexv = 0x40 | lowerv(reg, 0) | lowerv(reg2, 2) | (wide << 3);
	if (rexv != 0x40) {
		ass->write8(rexv);
	}
}

void rex(X64Assembler* ass, X64Pointer ptr, X64Register reg, bool wide) {
	auto rexv = 0x40 | lowerv(ptr, 0) | lowerv(reg, 2) | (wide << 3);
	if (rexv != 0x40) {
		ass->write8(rexv);
	}
}

X86Register x86reg(X64Register reg) {
	return static_cast<X86Register>(regv(reg) & 0xf7);
}

X86Pointer x86ptr(X64Pointer ptr) {
	return {x86reg(ptr.reg), ptr.offset};
}

X64Assembler::X64Assembler(int64_t baseAddress) :
	X86Assembler(baseAddress) {}

X64Assembler::~X64Assembler() {}

void X64Assembler::updateLabels() {
	for (auto const& update : m_labelUpdates) {
		this->rewrite32(update.m_address, m_labels[update.m_name] - update.m_address - 4);
	}
	// absolute is not absolute in 64 bit
	for (auto const& update : m_absoluteLabelUpdates) {
		this->rewrite32(update.m_address, m_labels[update.m_name] - update.m_address - 4);
	}
}

using enum X64Register;

void X64Assembler::nop() {
	X86Assembler::nop();
}

void X64Assembler::add(X64Register reg, int32_t value) {
	rex(this, reg, RAX, true);
	X86Assembler::add(x86reg(reg), value);
}

void X64Assembler::sub(X64Register reg, int32_t value) {
	rex(this, reg, RAX, true);
	X86Assembler::sub(x86reg(reg), value);
}

void X64Assembler::push(X64Register reg) {
	rex(this, reg, RAX, false);
	X86Assembler::push(x86reg(reg));
}

void X64Assembler::push(X64Pointer ptr) {
	rex(this, ptr, RAX, false);
	X86Assembler::push(x86ptr(ptr));
}

void X64Assembler::pop(X64Register reg) {
	rex(this, reg, RAX, false);
	X86Assembler::pop(x86reg(reg));
}

void X64Assembler::jmp(X64Register reg) {
	rex(this, reg, RAX, false);
	X86Assembler::jmp(x86reg(reg));
}

void X64Assembler::jmp(int64_t address) {
	X86Assembler::jmp(address);
}

void X64Assembler::jmp(std::string const& label) {
	X86Assembler::jmp(label);
}

void X64Assembler::jmpip(std::string const& label) {
	this->write8(0xff);
	this->write8(0x25);
	this->label32(label);
}

void X64Assembler::call(X64Register reg) {
	rex(this, reg, RAX, false);
	X86Assembler::call(x86reg(reg));
}

void X64Assembler::call(int64_t address) {
	X86Assembler::call(address);
}

void X64Assembler::call(std::string const& label) {
	X86Assembler::call(label);
}

void X64Assembler::callip(std::string const& label) {
	this->write8(0xff);
	this->write8(0x15);
	this->label32(label);
}

void X64Assembler::lea(X64Register reg, std::string const& label) {
	rex(this, RAX, reg, true);
	X86Assembler::lea(x86reg(reg), label);
}

void X64Assembler::movsd(X64Register reg, X64Pointer ptr) {
	rex(this, ptr, RAX, false);
	X86Assembler::movsd(x86reg(reg), x86ptr(ptr));
}

void X64Assembler::movsd(X64Pointer ptr, X64Register reg) {
	rex(this, ptr, RAX, false);
	X86Assembler::movsd(x86ptr(ptr), x86reg(reg));
}

void X64Assembler::movss(X64Register reg, X64Pointer ptr) {
	rex(this, ptr, RAX, false);
	X86Assembler::movss(x86reg(reg), x86ptr(ptr));
}

void X64Assembler::movss(X64Pointer ptr, X64Register reg) {
	rex(this, ptr, RAX, false);
	X86Assembler::movss(x86ptr(ptr), x86reg(reg));
}

void X64Assembler::movaps(X64Register reg, X64Pointer ptr) {
	rex(this, ptr, RAX, false);
	X86Assembler::movaps(x86reg(reg), x86ptr(ptr));
}

void X64Assembler::movaps(X64Pointer ptr, X64Register reg) {
	rex(this, ptr, RAX, false);
	X86Assembler::movaps(x86ptr(ptr), x86reg(reg));
}

void X64Assembler::mov(X64Register reg, int32_t value) {
	rex(this, reg, RAX, true);
	this->write8(0xc7);
	this->write8(0xc0 | regIdx(reg));
	this->write32(value);
}

void X64Assembler::mov(X64Register reg, X64Pointer ptr) {
	rex(this, ptr, reg, true);
	X86Assembler::mov(x86reg(reg), x86ptr(ptr));
}

void X64Assembler::mov(X64Pointer ptr, X64Register reg) {
	rex(this, ptr, reg, true);
	X86Assembler::mov(x86ptr(ptr), x86reg(reg));
}

void X64Assembler::mov(X64Register reg, X64Register reg2) {
	rex(this, reg, reg2, true);
	X86Assembler::mov(x86reg(reg), x86reg(reg2));
}

void X64Assembler::mov(X64Register reg, std::string const& label) {
	rex(this, RAX, reg, true);
	X86Assembler::mov(x86reg(reg), label);
}

void X64Assembler::shr(X64Register reg, uint8_t value) {
	rex(this, reg, RAX, true);
	X86Assembler::shr(x86reg(reg), value);
}

void X64Assembler::shl(X64Register reg, uint8_t value) {
	rex(this, reg, RAX, true);
	X86Assembler::shl(x86reg(reg), value);
}

void X64Assembler::xchg(X64Register reg, X64Register reg2) {
	rex(this, reg, reg2, true);
	X86Assembler::xchg(x86reg(reg), x86reg(reg2));
}