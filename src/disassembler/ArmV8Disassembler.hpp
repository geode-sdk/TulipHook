#pragma once

#include "../assembler/ArmV8Assembler.hpp"
#include "BaseDisassembler.hpp"

namespace tulip::hook {
    enum class ArmV8InstructionType {
        Other = 0,
        B,
        BL,
        LDR_Literal,
        ADR,
        ADRP,
        B_Cond,
        CB_,
        TBZ,
        TBNZ,
    };

    class ArmV8Instruction : public BaseInstruction {
    public:
        ArmV8InstructionType m_type = ArmV8InstructionType::Other;
        ArmV8Register m_src1 = ArmV8Register::X0;
        ArmV8Register m_src2 = ArmV8Register::X0;
        ArmV8Register m_dst1 = ArmV8Register::X0;
        ArmV8Register m_dst2 = ArmV8Register::X0;
        int32_t m_immediate = 0;
        ArmV8IndexKind m_indexKind = ArmV8IndexKind::PreIndex;
        int32_t m_other = 0;
        int64_t m_literal = 0;

        uint32_t m_rawInstruction = 0;
    };

	class ArmV8Disassembler : public BaseDisassembler {
	public:
		ArmV8Disassembler(int64_t baseAddress, std::vector<uint8_t> const& input);
		ArmV8Disassembler(ArmV8Disassembler const&) = delete;
		ArmV8Disassembler(ArmV8Disassembler&&) = delete;
		~ArmV8Disassembler();

        void handleB(ArmV8Instruction& instruction);
        void handleBL(ArmV8Instruction& instruction);
        void handleLDRLiteral(ArmV8Instruction& instruction);
        void handleADR(ArmV8Instruction& instruction);
        void handleADRP(ArmV8Instruction& instruction);
        void handleBCond(ArmV8Instruction& instruction);
        void handleTB_Z(ArmV8Instruction& instruction);
        void handleCB_(ArmV8Instruction& instruction);

        std::unique_ptr<BaseInstruction> disassembleNext() override;
	};
	
}