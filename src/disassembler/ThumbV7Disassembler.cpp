#include "ThumbV7Disassembler.hpp"

#include <cstring>

using namespace tulip::hook;

ThumbV7Disassembler::ThumbV7Disassembler(int64_t baseAddress, std::vector<uint8_t> const& input) :
    BaseDisassembler(baseAddress, input) {}

ThumbV7Disassembler::~ThumbV7Disassembler() = default;

ArmV7Register ThumbV7Disassembler::extractRegister(int startBit, uint32_t instruction) {
    return static_cast<ArmV7Register>(this->extractValue(startBit, 3, instruction));
}

ArmV7Register ThumbV7Disassembler::extractRegisterWide(int startBit, uint16_t instruction) {
    return static_cast<ArmV7Register>(this->extractValue(startBit, 4, instruction));
}

void ThumbV7Disassembler::handleB(ThumbV7Instruction& instruction) {
    instruction.m_type = ThumbV7InstructionType::B;
    instruction.m_immediate = this->extractValue(0, 8, instruction.m_rawInstruction) << 1;
    instruction.m_other = this->extractValue(8, 4, instruction.m_rawInstruction, false);
    instruction.m_literal = m_baseAddress + (instruction.m_immediate);
}

void ThumbV7Disassembler::handleBX(ThumbV7Instruction& instruction) {
    instruction.m_type = ThumbV7InstructionType::BX;
    instruction.m_src1 = this->extractRegisterWide(3, instruction.m_rawInstruction);
}

void ThumbV7Disassembler::handleBLX(ThumbV7Instruction& instruction) {
    instruction.m_type = ThumbV7InstructionType::BLX;
    instruction.m_src1 = this->extractRegisterWide(3, instruction.m_rawInstruction);
}

void ThumbV7Disassembler::handleLDRLiteral(ThumbV7Instruction& instruction) {
    instruction.m_type = ThumbV7InstructionType::LDR_Literal;
    instruction.m_dst1 = this->extractRegister(8, instruction.m_rawInstruction);
    instruction.m_immediate = this->extractValue(0, 8, instruction.m_rawInstruction, false) << 2;
    instruction.m_literal = (m_baseAddress & ~0x3ll) + (instruction.m_immediate);
}

void ThumbV7Disassembler::handleADR(ThumbV7Instruction& instruction) {
    instruction.m_type = ThumbV7InstructionType::ADR;
    instruction.m_dst1 = this->extractRegister(8, instruction.m_rawInstruction);
    instruction.m_immediate = this->extractValue(0, 8, instruction.m_rawInstruction, false) << 2;
    instruction.m_literal = (m_baseAddress & ~0x3ll) + (instruction.m_immediate);
}

void ThumbV7Disassembler::handleCB_(ThumbV7Instruction& instruction) {
    instruction.m_type = ThumbV7InstructionType::CB_;
    instruction.m_src1 = this->extractRegister(0, instruction.m_rawInstruction);
    instruction.m_immediate = this->extractValue(3, 5, instruction.m_rawInstruction, false) << 1;
    instruction.m_literal = m_baseAddress + (instruction.m_immediate);
}

void ThumbV7Disassembler::handleDataProc(ThumbV7Instruction& instruction) {
    instruction.m_type = ThumbV7InstructionType::DataProc;
    instruction.m_src1 = this->extractRegister(0, instruction.m_rawInstruction);
    instruction.m_dst1 = this->extractRegisterWide(3, instruction.m_rawInstruction);
}

void ThumbV7Disassembler::handleB_W(ThumbV7Instruction& instruction) {
    instruction.m_type = ThumbV7InstructionType::B_W;
    instruction.m_immediate = this->extractValue(0, 11, instruction.m_rawWideInstruction, false) << 1;
    instruction.m_immediate |= this->extractValue(16, 6, instruction.m_rawWideInstruction, false) << 12;
    instruction.m_immediate |= this->extractValue(11, 1, instruction.m_rawWideInstruction, false) << 18;
    instruction.m_immediate |= this->extractValue(13, 1, instruction.m_rawWideInstruction, false) << 19;
    instruction.m_immediate |= this->extractValue(26, 1, instruction.m_rawWideInstruction) << 20;
    instruction.m_other = this->extractValue(22, 4, instruction.m_rawWideInstruction, false);
    instruction.m_literal = m_baseAddress + (instruction.m_immediate);
}

void ThumbV7Disassembler::handleBL_W(ThumbV7Instruction& instruction) {
    auto typeDet = this->extractValue(12, 1, instruction.m_rawWideInstruction, false);
    instruction.m_type = typeDet == 1 ? ThumbV7InstructionType::BL_W : ThumbV7InstructionType::BLX_W;
    instruction.m_immediate = this->extractValue(0, 11, instruction.m_rawWideInstruction, false) << 1;
    instruction.m_immediate |= this->extractValue(16, 6, instruction.m_rawWideInstruction, false) << 12;
    instruction.m_immediate |= this->extractValue(11, 1, instruction.m_rawWideInstruction, false) << 18;
    instruction.m_immediate |= this->extractValue(13, 1, instruction.m_rawWideInstruction, false) << 19;
    instruction.m_immediate |= this->extractValue(26, 1, instruction.m_rawWideInstruction) << 20;
    instruction.m_other = this->extractValue(22, 4, instruction.m_rawWideInstruction, false);
    instruction.m_literal = m_baseAddress + (instruction.m_immediate);
}

void ThumbV7Disassembler::handleLDRLiteral_W(ThumbV7Instruction& instruction) {
    instruction.m_type = ThumbV7InstructionType::LDR_Literal_W;
    instruction.m_immediate = this->extractValue(0, 12, instruction.m_rawWideInstruction, false);
    instruction.m_src1 = this->extractRegisterWide(12, instruction.m_rawWideInstruction);
    if (this->extractValue(23, 1, instruction.m_rawWideInstruction) == 0) {
        instruction.m_immediate = -instruction.m_immediate;
    }
}

void ThumbV7Disassembler::handleADR_W(ThumbV7Instruction& instruction) {
    instruction.m_type = ThumbV7InstructionType::ADR_W;
    instruction.m_dst1 = this->extractRegisterWide(8, instruction.m_rawWideInstruction);
    instruction.m_immediate = this->extractValue(0, 8, instruction.m_rawWideInstruction, false);
    instruction.m_immediate |= this->extractValue(12, 3, instruction.m_rawWideInstruction, false) << 8;
    instruction.m_immediate |= this->extractValue(26, 1, instruction.m_rawWideInstruction, false) << 11;
    if (this->extractValue(23, 1, instruction.m_rawWideInstruction) == 1) {
        instruction.m_immediate = -instruction.m_immediate;
    }
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
// LDR_Literal_W,
// ADR_W,


std::unique_ptr<BaseInstruction> ThumbV7Disassembler::disassembleNext() {
    if (m_currentIndex >= m_input.size()) {
        return nullptr; // No more instructions to disassemble
    }

    uint16_t rawInstruction = 0;
    std::memcpy(&rawInstruction, &m_input[m_currentIndex], sizeof(rawInstruction));
    m_currentIndex += sizeof(rawInstruction);
    m_baseAddress += sizeof(rawInstruction);

    auto instruction = std::make_unique<ThumbV7Instruction>();
    instruction->m_rawInstruction = rawInstruction;

    // Determine the instruction type based on the raw instruction bits

    return instruction;
}