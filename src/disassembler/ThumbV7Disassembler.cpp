#include "ThumbV7Disassembler.hpp"

using namespace tulip::hook;

ThumbV7Disassembler::ThumbV7Disassembler(int64_t baseAddress, std::vector<uint8_t> const& input) :
    BaseDisassembler(baseAddress, input) {}

ThumbV7Disassembler::~ThumbV7Disassembler() = default;

namespace {
    int32_t extractValue(int startBit, int size, uint32_t instruction, bool signExtend = true) {
        auto val = (instruction >> startBit) & ((1 << size) - 1);
        if (signExtend && (val & (1 << (size - 1)))) {
            val |= ~((1 << size) - 1);
        }
        return val;
    }

    ArmV7Register extractRegister(int startBit, uint32_t instruction) {
        return static_cast<ArmV7Register>(extractValue(startBit, 3, instruction));
    }

    ArmV7Register extractRegisterWide(int startBit, uint16_t instruction) {
        return static_cast<ArmV7Register>(extractValue(startBit, 4, instruction));
    }
}

void ThumbV7Disassembler::handleB(ThumbV7Instruction& instruction) {
    instruction.m_type = ThumbV7InstructionType::B;
    instruction.m_immediate = extractValue(0, 8, instruction.m_rawInstruction) << 1;
    instruction.m_other = extractValue(8, 4, instruction.m_rawInstruction);
    instruction.m_literal = m_baseAddress + (instruction.m_immediate);
}

void ThumbV7Disassembler::handleBX(ThumbV7Instruction& instruction) {
    instruction.m_type = ThumbV7InstructionType::BX;
    instruction.m_src1 = extractRegisterWide(3, instruction.m_rawInstruction);
}

void ThumbV7Disassembler::handleBLX(ThumbV7Instruction& instruction) {
    instruction.m_type = ThumbV7InstructionType::BLX;
    instruction.m_src1 = extractRegisterWide(3, instruction.m_rawInstruction);
}

void ThumbV7Disassembler::handleLDRLiteral(ThumbV7Instruction& instruction) {
    instruction.m_type = ThumbV7InstructionType::LDR_Literal;
    instruction.m_src1 = extractRegister(8, instruction.m_rawInstruction);
    instruction.m_immediate = extractValue(0, 8, instruction.m_rawInstruction) << 2;
    instruction.m_literal = (m_baseAddress & ~0x3ll) + (instruction.m_immediate);
}

void ThumbV7Disassembler::handleADR(ThumbV7Instruction& instruction) {
    instruction.m_type = ThumbV7InstructionType::ADR;
    instruction.m_src1 = extractRegister(8, instruction.m_rawInstruction);
    instruction.m_immediate = extractValue(0, 8, instruction.m_rawInstruction) << 2;
    instruction.m_literal = (m_baseAddress & ~0x3ll) + (instruction.m_immediate);
}

void ThumbV7Disassembler::handleCB_(ThumbV7Instruction& instruction) {
    instruction.m_type = ThumbV7InstructionType::CB_;
    instruction.m_src1 = extractRegister(0, instruction.m_rawInstruction);
    instruction.m_immediate = extractValue(3, 5, instruction.m_rawInstruction) << 1;
    instruction.m_literal = m_baseAddress + (instruction.m_immediate);
}

void ThumbV7Disassembler::handleDataProc(ThumbV7Instruction& instruction) {
    instruction.m_type = ThumbV7InstructionType::DataProc;
    instruction.m_src1 = extractRegister(0, instruction.m_rawInstruction);
    instruction.m_dst1 = extractRegisterWide(3, instruction.m_rawInstruction);
}

void ThumbV7Disassembler::handleB_W(ThumbV7Instruction& instruction) {
    instruction.m_type = ThumbV7InstructionType::B_W;
    instruction.m_immediate = extractValue(0, 11, instruction.m_rawWideInstruction) << 1;
    instruction.m_immediate |= extractValue(16, 6, instruction.m_rawWideInstruction) << 12;
    instruction.m_immediate |= extractValue(11, 1, instruction.m_rawWideInstruction) << 18;
    instruction.m_immediate |= extractValue(13, 1, instruction.m_rawWideInstruction) << 19;
    instruction.m_immediate |= extractValue(26, 1, instruction.m_rawWideInstruction) << 20;
    instruction.m_other = extractValue(22, 4, instruction.m_rawWideInstruction);
    instruction.m_literal = m_baseAddress + (instruction.m_immediate);
}

//  B,
// BX,
// BLX,
// LDR_Literal,
// ADR,
// CB_,
// DataProc,
// B_W,
// BL_W,
// BLX_W,
// LDR_Literal_W,
// ADR_W,


std::unique_ptr<BaseInstruction> ThumbV7Disassembler::disassembleNext() {
    return nullptr;
}