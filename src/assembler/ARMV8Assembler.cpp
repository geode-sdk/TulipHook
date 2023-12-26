#include "ArmV8Assembler.hpp"

using namespace tulip::hook;

ArmV8Assembler::ArmV8Assembler(int64_t baseAddress) :
	BaseAssembler(baseAddress) {}

ArmV8Assembler::~ArmV8Assembler() {}

static uint32_t val(ArmV8Register reg) { return static_cast<uint32_t>(reg); }

void ArmV8Assembler::adrp(ArmV8Register dst, uint32_t imm) {
    const auto immlo = ((imm >> 12) & 3ull) << 29;
    const auto immhi = (imm >> 14) << 5;
    this->write32(0x90000000 | immlo | immhi | val(dst));
}

void ArmV8Assembler::add(ArmV8Register dst, ArmV8Register src, uint16_t imm) {
    const auto srcShifted = val(src) << 5;
    const auto immShifted = static_cast<uint32_t>(imm) << 10;
    this->write32(0x11000000 | srcShifted | immShifted | val(dst));
}

void ArmV8Assembler::br(ArmV8Register reg) {
    const auto shifted = val(reg) << 5;
    this->write32(0xD61F0000 | shifted);
}