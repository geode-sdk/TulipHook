#include "ArmV8Assembler.hpp"

using namespace tulip::hook;

ArmV8Assembler::ArmV8Assembler(int64_t baseAddress) :
	BaseAssembler(baseAddress) {}

ArmV8Assembler::~ArmV8Assembler() {}

void ArmV8Assembler::updateLabels() {
    // Handle LDR
	for (auto const& update : m_labelUpdates) {
        const auto diff = m_labels[update.m_name] - update.m_address;
        const auto opc = this->read32(update.m_address);
        this->rewrite32(update.m_address, opc | ((diff >> 2) << 5));
	}
}

using enum ArmV8Register;

static bool is_simd(ArmV8Register reg) { return static_cast<uint32_t>(reg) >= 0x40; }

static uint32_t val(ArmV8Register reg) {
    auto x = static_cast<uint32_t>(reg);
    if (is_simd(reg))
        x -= 0x40;
    return x;
}

void ArmV8Assembler::mov(ArmV8Register dst, ArmV8Register src) {
    const auto srcShifted = val(src) << 16;
    this->write32(0xAA0003E0 | srcShifted | val(dst));
}

void ArmV8Assembler::ldr(ArmV8Register dst, std::string const& label) {
    m_labelUpdates.push_back({this->currentAddress(), label, 4});
	this->write32((0x58ul << 24) | val(dst));
}

void ArmV8Assembler::ldp(ArmV8Register reg1, ArmV8Register reg2, ArmV8Register regBase, int16_t imm, ArmV8IndexKind kind) {
    using enum ArmV8IndexKind;

    uint32_t opc = 0;
    const auto use_simd = is_simd(reg1) && is_simd(reg2);

    switch (kind) {
        case PreIndex:
            opc = (use_simd ? 0x1B7 : 0x2A7) << 22;
            break;
        case PostIndex:
            opc = (use_simd ? 0x1B3 : 0x2A3) << 22;
            break;
        case SignedOffset:
            opc = (use_simd ? 0x1B5 : 0x2A5) << 22;
            break;
    }

    const auto reg2Shifted = val(reg2) << 10;
    const auto regBaseShifted = val(regBase) << 5;
    const auto immShifted = static_cast<uint32_t>((imm >> 3) & 0x7F) << 15;

    this->write32(opc | reg2Shifted | regBaseShifted | immShifted | val(reg1));
}

void ArmV8Assembler::stp(ArmV8Register reg1, ArmV8Register reg2, ArmV8Register regBase, int16_t imm, ArmV8IndexKind kind) {
    using enum ArmV8IndexKind;

    uint32_t opc = 0;
    const auto use_simd = is_simd(reg1) && is_simd(reg2);

    switch (kind) {
        case PreIndex:
            opc = (use_simd ? 0x1B6 : 0x2A6) << 22;
            break;
        case PostIndex:
            opc = (use_simd ? 0x1B2 : 0x2A2) << 22;
            break;
        case SignedOffset:
            opc = (use_simd ? 0x1B4 : 0x2A4) << 22;
            break;
    }

    const auto reg2Shifted = (val(reg2) << 10);
    const auto regBaseShifted = (val(regBase) << 5);
    const auto immShifted = static_cast<uint32_t>((imm >> 3) & 0x7F) << 15;

    this->write32(opc | reg2Shifted | regBaseShifted | immShifted | val(reg1));
}

void ArmV8Assembler::adrp(ArmV8Register dst, int64_t imm) {
    const auto immlo = ((imm >> 12) & 3ull) << 29;
    const auto immhi = ((imm >> 14) & 0x7ffffull) << 5;
    this->write32(0x90000000 | immlo | immhi | val(dst));
}

void ArmV8Assembler::add(ArmV8Register dst, ArmV8Register src, uint16_t imm) {
    const auto srcShifted = val(src) << 5;
    const auto immShifted = (static_cast<uint32_t>(imm) & 0xFFF) << 10;
    this->write32(0x91000000 | srcShifted | immShifted | val(dst));
}

void ArmV8Assembler::b(uint32_t imm) {
    this->write32(0x14000000 | ((imm >> 2) & 0x3FFFFFF));
}

void ArmV8Assembler::bl(uint32_t imm) {
    this->write32(0x94000000 | ((imm >> 2) & 0x3FFFFFF));
}

void ArmV8Assembler::br(ArmV8Register reg) {
    const auto shifted = val(reg) << 5;
    this->write32(0xD61F0000 | shifted);
}

void ArmV8Assembler::blr(ArmV8Register reg) {
    const auto shifted = val(reg) << 5;
    this->write32(0xD63F0000 | shifted);
}

void ArmV8Assembler::push(ArmV8RegisterArray const& array) {
    using enum ArmV8IndexKind;

    const auto alignedSize = array.size() & ~1ull;
    for (auto i = 0u; i < alignedSize; i += 2)
        this->stp(array[i], array[i + 1], SP, -0x10, PreIndex);
}

void ArmV8Assembler::pop(ArmV8RegisterArray const& array) {
    using enum ArmV8IndexKind;

    const auto alignedSize = array.size() & ~1ull;
    for (auto i = 0u; i < alignedSize; i += 2)
        this->ldp(array[alignedSize - i - 2], array[alignedSize - i - 1], SP, 0x10, PostIndex);
}

void ArmV8Assembler::ldr(ArmV8Register dst, ArmV8Register src, int32_t imm) {
    const auto srcShifted = val(src) << 5;
    const auto offsetShifted = ((imm >> 2) & 0x3FFF) << 10;
    const auto simdShifted = is_simd(dst) << 26;
    this->write32(0xf9400000 | srcShifted | offsetShifted | val(dst) | simdShifted);
}
void ArmV8Assembler::ldr(ArmV8Register dst, int32_t literal) {
    const auto literalShifted = ((literal >> 2) & 0x7FFFF) << 5;
    const auto simdShifted = is_simd(dst) << 26;
    this->write32(0x58000000 | literalShifted | val(dst) | simdShifted);
}

void ArmV8Assembler::tbz(ArmV8Register reg, int32_t bit, int32_t imm) {
    const auto literalShifted = ((imm >> 2) & 0x3FFF) << 5;
    const auto bitShifted = (bit & 0x1F) << 19 | ((bit >> 5) & 1) << 31;
    this->write32(0x36000000 | literalShifted | bitShifted | val(reg));
}
void ArmV8Assembler::tbnz(ArmV8Register reg, int32_t bit, int32_t imm) {
    const auto literalShifted = ((imm >> 2) & 0x3FFF) << 5;
    const auto bitShifted = (bit & 0x1F) << 19 | ((bit >> 5) & 1) << 31;
    this->write32(0x37000000 | literalShifted | bitShifted | val(reg));
}

void ArmV8Assembler::nop() { this->write32(0xD503201F); }