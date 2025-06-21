#include "ArmV8Disassembler.hpp"

using namespace tulip::hook;

ArmV8Disassembler::ArmV8Disassembler(int64_t baseAddress, std::vector<uint8_t> const& input) :
    BaseDisassembler(baseAddress, input) {}

ArmV8Disassembler::~ArmV8Disassembler() = default;

ArmV8Register ArmV8Disassembler::extractRegister(int startBit, uint32_t instruction) {
    return static_cast<ArmV8Register>(this->extractValue(startBit, 5, instruction));
}

void ArmV8Disassembler::handleB(ArmV8Instruction& instruction) {
    instruction.m_type = ArmV8InstructionType::B;
    instruction.m_immediate = this->extractValue(0, 26, instruction.m_rawInstruction) << 2;
    instruction.m_literal = m_baseAddress + (instruction.m_immediate);
}

void ArmV8Disassembler::handleBL(ArmV8Instruction& instruction) {
    instruction.m_type = ArmV8InstructionType::BL;
    instruction.m_immediate = this->extractValue(0, 26, instruction.m_rawInstruction) << 2;
    instruction.m_literal = m_baseAddress + (instruction.m_immediate);
}

void ArmV8Disassembler::handleLDRLiteral(ArmV8Instruction& instruction) {
    instruction.m_type = ArmV8InstructionType::LDR_Literal;
    instruction.m_dst1 = this->extractRegister(0, instruction.m_rawInstruction);
    instruction.m_immediate = this->extractValue(5, 19, instruction.m_rawInstruction) << 2;
    instruction.m_literal = m_baseAddress + (instruction.m_immediate);

}

void ArmV8Disassembler::handleADR(ArmV8Instruction& instruction) {
    instruction.m_type = ArmV8InstructionType::ADR;
    instruction.m_dst1 = this->extractRegister(0, instruction.m_rawInstruction);
    instruction.m_immediate = this->extractValue(29, 2, instruction.m_rawInstruction, false);
    instruction.m_immediate |= this->extractValue(5, 19, instruction.m_rawInstruction) << 2;
    instruction.m_literal = m_baseAddress + (instruction.m_immediate);
}

void ArmV8Disassembler::handleADRP(ArmV8Instruction& instruction) {
    instruction.m_type = ArmV8InstructionType::ADRP;
    instruction.m_dst1 = this->extractRegister(0, instruction.m_rawInstruction);
    instruction.m_immediate = this->extractValue(29, 2, instruction.m_rawInstruction, false) << 12;
    instruction.m_immediate |= this->extractValue(5, 19, instruction.m_rawInstruction) << 14;
    instruction.m_literal = (m_baseAddress + (instruction.m_immediate)) & ~0xFFFll;
}

void ArmV8Disassembler::handleBCond(ArmV8Instruction& instruction) {
    instruction.m_type = ArmV8InstructionType::B_Cond;
    instruction.m_other = this->extractValue(0, 5, instruction.m_rawInstruction);
    instruction.m_immediate = this->extractValue(5, 19, instruction.m_rawInstruction) << 2;
    instruction.m_literal = m_baseAddress + (instruction.m_immediate);
}

void ArmV8Disassembler::handleTB_Z(ArmV8Instruction& instruction) {
    instruction.m_type = this->extractValue(24, 1, instruction.m_rawInstruction) == 0 ? ArmV8InstructionType::TBZ : ArmV8InstructionType::TBNZ;
    instruction.m_src1 = this->extractRegister(0, instruction.m_rawInstruction);
    instruction.m_other = this->extractValue(19, 5, instruction.m_rawInstruction, false);
    instruction.m_other |= this->extractValue(31, 1, instruction.m_rawInstruction) << 5;
    instruction.m_immediate = this->extractValue(5, 14, instruction.m_rawInstruction) << 2;
    instruction.m_literal = m_baseAddress + (instruction.m_immediate);
}

void ArmV8Disassembler::handleCB_(ArmV8Instruction& instruction) {
    instruction.m_type = ArmV8InstructionType::CB_;
    instruction.m_src1 = this->extractRegister(0, instruction.m_rawInstruction);
    instruction.m_immediate = this->extractValue(5, 9, instruction.m_rawInstruction) << 2;
    instruction.m_literal = m_baseAddress + (instruction.m_immediate);
}

std::unique_ptr<BaseInstruction> ArmV8Disassembler::disassembleNext() {
    if (m_currentIndex >= m_input.size()) {
        return nullptr; // No more instructions to disassemble
    }

    uint32_t rawInstruction = 0;
    std::memcpy(&rawInstruction, &m_input[m_currentIndex], sizeof(rawInstruction));

    auto instruction = std::make_unique<ArmV8Instruction>();
    instruction->m_rawInstruction = rawInstruction;

    // Determine the instruction type based on the raw instruction bits
    if ((rawInstruction & 0x7C000000) == 0x14000000) { // B or BL
        if ((rawInstruction & 0x80000000) != 0) {
            this->handleBL(*instruction);
        } else {
            this->handleB(*instruction);
        }
    } else if ((rawInstruction & 0x3B000000) == 0x18000000) { // LDR literal
        this->handleLDRLiteral(*instruction);
    } else if ((rawInstruction & 0x1F000000) == 0x10000000) { // ADR or ADRP
        if ((rawInstruction & 0x80000000) != 0) {
            this->handleADRP(*instruction);
        } else {
            this->handleADR(*instruction);
        }
    } else if ((rawInstruction & 0x7E000000) == 0x74000000) { // CB_
        this->handleCB_(*instruction);
    } else if ((rawInstruction & 0xFE000000) == 0x54000000) { // B_Cond
        this->handleBCond(*instruction);
    } else if ((rawInstruction & 0x7E000000) == 0x36000000) { // TB_Z
        this->handleTB_Z(*instruction);
    }

    m_currentIndex += sizeof(rawInstruction);
    m_baseAddress += sizeof(rawInstruction);

    return instruction;
}