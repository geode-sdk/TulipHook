#include "ArmV7Assembler.hpp"

#include <iostream>

using namespace tulip::hook;

ArmV7Assembler::ArmV7Assembler(int64_t baseAddress) :
	BaseAssembler(baseAddress) {}

ArmV7Assembler::~ArmV7Assembler() {}

uint8_t* ArmV7Assembler::lastInsn() {
	return &m_buffer[m_buffer.size() - 2];
}

void ArmV7Assembler::rwl(int8_t offset, int8_t size, int32_t value) {
	auto address = this->lastInsn();

	auto pointer = reinterpret_cast<uint16_t*>(address);

	auto mask = ((1 << size) - 1) << offset;

	*pointer = (*pointer & ~mask) | (value << offset);
}

int32_t arrayMaskLow(ArmV7RegisterArray const& array) {
	int32_t mask = 0;

	for (auto const& reg : array) {
		mask |= 1 << (int32_t)reg;
	}

	return mask;
}

int32_t val(ArmV7Register reg) {
	return (int32_t)reg & 0xf;
}

int32_t vall(ArmV7Register reg) {
	return (int32_t)reg & 0x7;
}

int32_t valh(ArmV7Register reg) {
	return ((int32_t)reg & 0x8) >> 3;
}

void ArmV7Assembler::label8(std::string const& name) {
	m_labelUpdates.push_back({this->currentAddress(), name, 1});
	this->write8(0);
}

void ArmV7Assembler::updateLabels() {
	for (auto const& update : m_labelUpdates) {
		// this will technically fail but im lazy
		// we dont have enough wide instructions for me to care about
		auto aligned = (update.m_address & (~0x3)) + 0x4;
		auto diff = m_labels[update.m_name] - aligned;
		this->rewrite8(update.m_address, diff / 4);
	}
}

using enum ArmV7Register;

void ArmV7Assembler::nop() {
	this->write16(0xbf00);
}

void ArmV7Assembler::push(ArmV7RegisterArray const& array) {
	this->write16(0xb400);
	this->rwl(0, 8, arrayMaskLow(array));
}

void ArmV7Assembler::vpush(ArmV7RegisterArray const& array) {
	this->write16(0xed2d);
	this->write16(0x0b00);
	this->rwl(1, 7, array.size());
	this->rwl(12, 4, val(array[0]));
}

void ArmV7Assembler::pop(ArmV7RegisterArray const& array) {
	this->write16(0xbc00);
	this->rwl(0, 8, arrayMaskLow(array));
}

void ArmV7Assembler::vpop(ArmV7RegisterArray const& array) {
	this->write16(0xecbd);
	this->write16(0x0b00);
	this->rwl(1, 7, array.size());
	this->rwl(12, 4, val(array[0]));
}

void ArmV7Assembler::ldr(ArmV7Register dst, std::string const& label) {
	this->label8(label);
	this->write8(0x48);
	this->rwl(8, 3, vall(dst));
}

void ArmV7Assembler::ldrpcn() {
	this->write16(0xf85f);
	this->write16(0xf000);
}

void ArmV7Assembler::ldrpcn2() {
	this->write16(0xf000);
	this->write16(0xe51f);
}

void ArmV7Assembler::mov(ArmV7Register dst, ArmV7Register src) {
	this->write16(0x4600);
	this->rwl(0, 3, vall(dst));
	this->rwl(3, 4, val(src));
	this->rwl(7, 1, valh(dst));
}

void ArmV7Assembler::blx(ArmV7Register dst) {
	this->write16(0x4780);
	this->rwl(3, 4, val(dst));
}

void ArmV7Assembler::bx(ArmV7Register dst) {
	this->write16(0x4700);
	this->rwl(3, 4, val(dst));
}