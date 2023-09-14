#include "Arm7Assembler.hpp"

using namespace tulip::hook;

Arm7Assembler::Arm7Assembler(int64_t baseAddress) :
	BaseAssembler(baseAddress) {}

Arm7Assembler::~Arm7Assembler() {}

uint8_t* Arm7Assembler::lastInsn() {
	return &m_buffer[m_buffer.size() - 2];
}

void Arm7Assembler::rwl(int8_t offset, int8_t size, int32_t value) {
	auto address = this->lastInsn();

	auto pointer = reinterpret_cast<uint32_t*>(address);

	auto mask = ((1 << size) - 1) << offset;

	*pointer = (*pointer & ~mask) | (value << offset);
}

int32_t arrayMaskLow(Arm7RegisterArray const& array) {
	int32_t mask = 0;

	for (auto const& reg : array) {
		mask |= 1 << (int32_t)reg;
	}

	return mask;
}

int32_t val(Arm7Register reg) {
	return (int32_t)reg & 0x15;
}

void Arm7Assembler::label8(std::string const& name) {
	m_labelUpdates.push_back({this->currentAddress(), name, 1});
	this->write8(0);
}

void Arm7Assembler::updateLabels() {
	for (auto const& update : m_labelUpdates) {
		this->rewrite8(update.m_address, m_labels[update.m_name]);
	}
}

using enum Arm7Register;

void Arm7Assembler::nop() {
	this->write16(0xbf00);
}

void Arm7Assembler::push(Arm7RegisterArray const& array) {
	this->write16(0xb400);
	this->rwl(0, 8, arrayMaskLow(array));
}

void Arm7Assembler::vpush(Arm7RegisterArray const& array) {
	this->write32(0xed2d0b00);
	this->rwl(1, 7, array.size());
	this->rwl(12, 4, val(array[0]));
}

void Arm7Assembler::pop(Arm7RegisterArray const& array) {
	this->write16(0xbc00);
	this->rwl(0, 8, arrayMaskLow(array));
}

void Arm7Assembler::vpop(Arm7RegisterArray const& array) {
	this->write32(0xecbd0b00);
	this->rwl(1, 7, array.size());
	this->rwl(12, 4, val(array[0]));
}

void Arm7Assembler::ldr(Arm7Register dst, std::string const& label) {
	this->label8(label);
	this->write8(0x48);
	this->rwl(8, 3, (int32_t)dst);
}

void Arm7Assembler::ldrw(Arm7Register dst, std::string const& label) {
	// it supports 12 bit label but im lazy
	this->label8(label);
	this->write8(0x00);
	this->rwl(12, 4, (int32_t)dst);
	this->write16(0xf8df);
}

void Arm7Assembler::mov(Arm7Register dst, Arm7Register src) {
	this->write16(0x4600);
	this->rwl(0, 3, (int32_t)dst);
	this->rwl(3, 4, (int32_t)src);
}

void Arm7Assembler::blx(Arm7Register dst) {
	this->write16(0x4780);
	this->rwl(3, 4, (int32_t)dst);
}

void Arm7Assembler::bx(Arm7Register src) {
	this->write16(0x4700);
	this->rwl(3, 4, (int32_t)src);
}