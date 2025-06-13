#include "../src/assembler/ArmV8Assembler.hpp"
#include "../src/disassembler/ArmV8Disassembler.hpp"
#include "Assembler.hpp"

#include <gtest/gtest.h>

using namespace tulip::hook;

using enum ArmV8Register;

TEST(ArmV8AssemblerTest, ADRPReloc) {
	ArmV8Assembler a(0xc312a0);
    ArmV8Disassembler d(0x451344, {0xa8, 0x22, 0x00, 0xd0});
	auto instruction = d.disassembleNext();
    auto ins = static_cast<ArmV8Instruction*>(instruction.get());
    EXPECT_EQ(ins->m_type, ArmV8InstructionType::ADRP);
    EXPECT_EQ(ins->m_dst1, ArmV8Register::X8);
    EXPECT_EQ(ins->m_immediate, 0x456);
    EXPECT_EQ(ins->m_literal, 0x8a7000);

    auto const newOffset = a.m_baseAddress - 0x8a7000;
    a.adrp(X8, newOffset);

    ArmV8Disassembler d2(a.m_baseAddress - 4, a.m_buffer);
    EXPECT_EQ(ins->m_literal, 0x8a7000);
}