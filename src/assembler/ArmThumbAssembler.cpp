#include "ArmThumbAssembler.hpp"

using namespace tulip::hook;

ArmThumbAssembler::ArmThumbAssembler(int64_t baseAddress) :
	BaseAssembler(baseAddress) {}

ArmThumbAssembler::~ArmThumbAssembler() {}

uint8_t* ArmThumbAssembler::lastInsn() {
	return &m_buffer[m_buffer.size() - 2];
}

void ArmThumbAssembler::rwl(int8_t offset, int8_t size, int32_t value) {
	auto address = this->lastInsn();

	auto pointer = reinterpret_cast<uint32_t*>(address);

	auto mask = ((1 << size) - 1) << offset;

	*pointer = (*pointer & ~mask) | (value << offset);
}

int32_t arrayMaskLow(ArmRegisterArray const& array) {
	int32_t mask = 0;

	for (auto const& reg : array) {
		mask |= 1 << (int32_t)reg;
	}

	return mask;
}

int32_t val(ArmRegister reg) {
	return (int32_t)reg & 0x15;
}

void ArmThumbAssembler::label8(std::string const& name) {
	m_labelUpdates.push_back({this->currentAddress(), name, 1});
	this->write8(0);
}

void ArmThumbAssembler::updateLabels() {
	for (auto const& update : m_labelUpdates) {
		this->rewrite8(update.m_address, m_labels[update.m_name]);
	}
}

using enum ArmRegister;

void ArmThumbAssembler::nop() {
	this->write16(0xbf00);
}

void ArmThumbAssembler::push(ArmRegisterArray const& array) {
	this->write16(0xb400);
	this->rwl(0, 8, arrayMaskLow(array));
}

void ArmThumbAssembler::vpush(ArmRegisterArray const& array) {
	this->write32(0xed2d0b00);
	this->rwl(1, 7, array.size());
	this->rwl(12, 4, val(array[0]));
}

void ArmThumbAssembler::pop(ArmRegisterArray const& array) {
	this->write16(0xbc00);
	this->rwl(0, 8, arrayMaskLow(array));
}

void ArmThumbAssembler::vpop(ArmRegisterArray const& array) {
	this->write32(0xecbd0b00);
	this->rwl(1, 7, array.size());
	this->rwl(12, 4, val(array[0]));
}

void ArmThumbAssembler::ldr(ArmRegister dst, std::string const& label) {
	this->label8(label);
	this->write8(0x48);
	this->rwl(8, 3, (int32_t)dst);
}

void ArmThumbAssembler::mov(ArmRegister dst, ArmRegister src) {
	this->write16(0x4600);
	this->rwl(0, 3, (int32_t)dst);
	this->rwl(3, 4, (int32_t)src);
}

void ArmThumbAssembler::blx(ArmRegister dst) {
	this->write16(0x4780);
	this->rwl(3, 4, (int32_t)dst);
}

void ArmThumbAssembler::bx(ArmRegister src) {
	this->write16(0x4700);
	this->rwl(3, 4, (int32_t)src);
}