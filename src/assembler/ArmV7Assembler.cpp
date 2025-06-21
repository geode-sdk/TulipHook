#include "ArmV7Assembler.hpp"

using namespace tulip::hook;

ArmV7Assembler::ArmV7Assembler(int64_t baseAddress) :
    BaseAssembler(baseAddress) {}

ArmV7Assembler::~ArmV7Assembler() {}

static int32_t val(ArmV7Register reg) {
    return (int32_t)reg & 0xf;
}

static int32_t vall(ArmV7Register reg) {
    return (int32_t)reg & 0x7;
}

static int32_t valh(ArmV7Register reg) {
    return ((int32_t)reg & 0x8) >> 3;
}

uint8_t* ArmV7Assembler::lastInsn() {
    return &m_buffer[m_buffer.size() - 4];
}

void ArmV7Assembler::rwl(int8_t offset, int8_t size, int32_t value) {
    auto address = this->lastInsn();
    auto pointer = reinterpret_cast<uint16_t*>(address);
    auto mask = ((1 << size) - 1) << offset;
    *pointer = (*pointer & ~mask) | (value << offset);
}

void ArmV7Assembler::ldr(ArmV7Register dst, ArmV7Register src, int32_t offset) {
    this->write16(0x0000);
    this->rwl(0, 12, offset);
    this->rwl(12, 4, val(dst));
    this->write16(0xe510);
    this->rwl(0, 4, val(src));
    if (offset < 0) {
        this->rwl(7, 1, 1);
    }
}