#include "ThumbV7Assembler.hpp"

using namespace tulip::hook;

ThumbV7Assembler::ThumbV7Assembler(int64_t baseAddress) :
    BaseAssembler(baseAddress) {}

ThumbV7Assembler::~ThumbV7Assembler() {}

uint8_t* ThumbV7Assembler::lastInsn() {
    return &m_buffer[m_buffer.size() - 2];
}

void ThumbV7Assembler::rwl(int8_t offset, int8_t size, int32_t value) {
    auto address = this->lastInsn();

    auto pointer = reinterpret_cast<uint16_t*>(address);

    auto mask = ((1 << size) - 1) << offset;

    *pointer = (*pointer & ~mask) | (value << offset);
}

static int32_t arrayMaskLow(ArmV7RegisterArray const& array) {
    int32_t mask = 0;

    for (auto const& reg : array) {
        mask |= 1 << (int32_t)reg;
    }

    return mask;
}

static int32_t val(ArmV7Register reg) {
    return (int32_t)reg & 0xf;
}

static int32_t vall(ArmV7Register reg) {
    return (int32_t)reg & 0x7;
}

static int32_t valh(ArmV7Register reg) {
    return ((int32_t)reg & 0x8) >> 3;
}

void ThumbV7Assembler::label8(std::string const& name) {
    m_labelUpdates.push_back({this->currentAddress(), name, 1, 0});
    this->write8(0);
}

void ThumbV7Assembler::updateLabels() {
    for (auto const& update : m_labelUpdates) {
        // this will technically fail but im lazy
        // we dont have enough wide instructions for me to care about
        auto aligned = (update.m_address & (~0x3)) + 0x4;
        auto diff = m_labels[update.m_name] - aligned;
        this->rewrite8(update.m_address, diff / 4);
    }
}

using enum ArmV7Register;

void ThumbV7Assembler::nop() {
    this->write16(0xbf00);
}

void ThumbV7Assembler::padWide() {
    if ((m_baseAddress + m_buffer.size()) % 4 != 0) {
        this->nop();
    }
}

void ThumbV7Assembler::pushw(ArmV7RegisterArray const& array) {
    this->padWide();
    this->write16(0xe92d);
    this->write16(0x0000);
    this->rwl(0, 16, arrayMaskLow(array));
}

void ThumbV7Assembler::vpush(ArmV7RegisterArray const& array) {
    this->padWide();
    this->write16(0xed2d);
    this->write16(0x0b00);
    this->rwl(1, 7, array.size());
    this->rwl(12, 4, val(array[0]));
}

void ThumbV7Assembler::popw(ArmV7RegisterArray const& array) {
    this->padWide();
    this->write16(0xe8bd);
    this->write16(0x0000);
    this->rwl(0, 16, arrayMaskLow(array));
}

void ThumbV7Assembler::vpop(ArmV7RegisterArray const& array) {
    this->padWide();
    this->write16(0xecbd);
    this->write16(0x0b00);
    this->rwl(1, 7, array.size());
    this->rwl(12, 4, val(array[0]));
}

void ThumbV7Assembler::ldr(ArmV7Register dst, std::string const& label) {
    this->label8(label);
    this->write8(0x48);
    this->rwl(8, 3, vall(dst));
}

void ThumbV7Assembler::ldr(ArmV7Register dst, ArmV7Register src, int32_t offset) {
    if (src == ArmV7Register::SP) {
        this->write16(0x9800);
        this->rwl(8, 3, vall(dst));
        this->rwl(0, 8, offset >> 2);
    }
    else {
        this->write16(0x6800);
        this->rwl(0, 3, vall(dst));
        this->rwl(3, 3, vall(src));
        this->rwl(6, 7, offset >> 2);
    }
}
void ThumbV7Assembler::str(ArmV7Register src, ArmV7Register dst, int32_t offset) {
    if (dst == ArmV7Register::SP) {
        this->write16(0x9000);
        this->rwl(8, 3, vall(src));
        this->rwl(0, 8, offset >> 2);
    }
    else {
        this->write16(0x6000);
        this->rwl(0, 3, vall(src));
        this->rwl(3, 3, vall(dst));
        this->rwl(6, 7, offset >> 2);
    }
}

void ThumbV7Assembler::vldr(ArmV7Register dst, ArmV7Register src, int32_t offset) {
    this->padWide();
    this->write16(0xed90);
    this->rwl(0, 4, val(src));
    this->write16(0x0b00);
    this->rwl(0, 8, offset >> 2);
    this->rwl(12, 4, val(dst));
}

void ThumbV7Assembler::vstr(ArmV7Register src, ArmV7Register dst, int32_t offset) {
    this->padWide();
    this->write16(0xed80);
    this->rwl(0, 4, val(dst));
    this->write16(0x0b00);
    this->rwl(0, 8, offset >> 2);
    this->rwl(12, 4, val(src));
}

void ThumbV7Assembler::ldrw(ArmV7Register dst, ArmV7Register src, int32_t offset) {
    this->padWide();
    if (src == ArmV7Register::PC) {
        this->write16(0xf850);
        this->rwl(0, 4, val(src));
        if (offset > 0) this->rwl(7, 1, 1);
        this->write16(0x0000);
        this->rwl(0, 12, std::fabs(offset));
        this->rwl(12, 4, val(dst));
    }
    else if (offset < 0) {
        this->write16(0xf850);
        this->rwl(0, 4, val(src));
        this->write16(0x0000);
        this->rwl(0, 8, std::fabs(offset));
        this->rwl(12, 4, val(dst));
    }
    else {
        this->write16(0xf8d0);
        this->rwl(0, 4, val(src));
        this->write16(0x0000);
        this->rwl(0, 8, offset);
        this->rwl(12, 4, val(dst));
    }
}

void ThumbV7Assembler::strw(ArmV7Register src, ArmV7Register dst, int32_t offset) {
    this->padWide();
    this->write16(0xf8c0);
    this->rwl(0, 4, val(src));
    this->write16(0x0000);
    this->rwl(0, 8, offset);
    this->rwl(12, 4, val(dst));
}

void ThumbV7Assembler::mov(ArmV7Register dst, ArmV7Register src) {
    this->write16(0x4600);
    this->rwl(0, 3, vall(dst));
    this->rwl(3, 4, val(src));
    this->rwl(7, 1, valh(dst));
}

void ThumbV7Assembler::sub(ArmV7Register dst, ArmV7Register src, int16_t imm) {
    if (dst == ArmV7Register::SP && src == ArmV7Register::SP) {
        this->write16(0xb080);
        this->rwl(0, 7, imm >> 2);
    }
    // unimplemented
}

void ThumbV7Assembler::add(ArmV7Register dst, ArmV7Register src, int16_t imm) {
    if (dst == ArmV7Register::SP && src == ArmV7Register::SP) {
        this->write16(0xb000);
        this->rwl(0, 7, imm >> 2);
    }
    // unimplemented
}

void ThumbV7Assembler::blx(ArmV7Register dst) {
    this->write16(0x4780);
    this->rwl(3, 4, val(dst));
}

void ThumbV7Assembler::bx(ArmV7Register dst) {
    this->write16(0x4700);
    this->rwl(3, 4, val(dst));
}
