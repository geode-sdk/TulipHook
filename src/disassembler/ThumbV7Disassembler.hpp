#pragma once

#include "../assembler/ThumbV7Assembler.hpp"
#include "BaseDisassembler.hpp"

namespace tulip::hook {
    enum class ThumbV7InstructionType {
        Other = 0,
        B,
        BX,
        BLX,
        LDR_Literal,
        ADR,
        CB_,
        DataProc,
        B_W,
        BL_W,
        BLX_W,
        LDR_Literal_W,
        ADR_W,
    };

    class ThumbV7Instruction : public BaseInstruction {
    public:
        ThumbV7InstructionType m_type = ThumbV7InstructionType::Other;
        ArmV7Register m_src1 = ArmV7Register::R0;
        ArmV7Register m_src2 = ArmV7Register::R0;
        ArmV7Register m_dst1 = ArmV7Register::R0;
        ArmV7Register m_dst2 = ArmV7Register::R0;
        int32_t m_immediate = 0;
        int32_t m_other = 0;
        int64_t m_literal = 0;

        uint16_t m_rawInstruction = 0;
        uint32_t m_rawWideInstruction = 0;
    };

	class ThumbV7Disassembler : public BaseDisassembler {
	public:
		ThumbV7Disassembler(int64_t baseAddress, std::vector<uint8_t> const& input);
		ThumbV7Disassembler(ThumbV7Disassembler const&) = delete;
		ThumbV7Disassembler(ThumbV7Disassembler&&) = delete;
		~ThumbV7Disassembler();

        void handleB(ThumbV7Instruction& instruction);
        void handleBX(ThumbV7Instruction& instruction);
        void handleBLX(ThumbV7Instruction& instruction);
        void handleLDRLiteral(ThumbV7Instruction& instruction);
        void handleADR(ThumbV7Instruction& instruction);
        void handleCB_(ThumbV7Instruction& instruction);
        void handleDataProc(ThumbV7Instruction& instruction);
        void handleB_W(ThumbV7Instruction& instruction);
        void handleBL_W(ThumbV7Instruction& instruction);
        void handleBLX_W(ThumbV7Instruction& instruction);
        void handleLDRLiteral_W(ThumbV7Instruction& instruction);
        void handleADR_W(ThumbV7Instruction& instruction);

        std::unique_ptr<BaseInstruction> disassembleNext() override;
	};
	
}