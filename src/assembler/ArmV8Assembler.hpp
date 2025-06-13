#pragma once

#include "BaseAssembler.hpp"

namespace tulip::hook {

	enum class ArmV8Register : uint8_t {
		// 64-bit
		X0 = 0,
		X1,
		X2,
		X3,
		X4,
		X5,
		X6,
		X7,
		X8,
		X9,
		X10,
		X11,
		X12,
		X13,
		X14,
		X15,
		X16,
		X17,
		X18,
		X19,
		X20,
		X21,
		X22,
		X23,
		X24,
		X25,
		X26,
		X27,
		X28,
		X29,
		X30,
		SP,
		PC,
		D0 = 0x40,
		D1,
		D2,
		D3,
		D4,
		D5,
		D6,
		D7,
		D8,
		D9,
		D10,
		D11,
		D12,
		D13,
		D14,
		D15,
		D16,
		D17,
		D18,
		D19,
		D20,
		D21,
		D22,
		D23,
		D24,
		D25,
		D26,
		D27,
		D28,
		D29,
		D30,
		D31,
	};

	enum class ArmV8IndexKind : uint8_t {
		PreIndex,
		PostIndex,
		SignedOffset,
	};

	using ArmV8RegisterArray = std::vector<ArmV8Register>;

	class ArmV8Assembler : public BaseAssembler {
	public:
		ArmV8Assembler(int64_t baseAddress);
		ArmV8Assembler(ArmV8Assembler const&) = delete;
		ArmV8Assembler(ArmV8Assembler&&) = delete;
		~ArmV8Assembler();

		void updateLabels() override;

		/* Instructions */

		void mov(ArmV8Register dst, ArmV8Register src);
		void ldr(ArmV8Register dst, std::string const& label);
		void ldp(ArmV8Register reg1, ArmV8Register reg2, ArmV8Register regBase, int16_t imm, ArmV8IndexKind kind);
		void stp(ArmV8Register reg1, ArmV8Register reg2, ArmV8Register regBase, int16_t imm, ArmV8IndexKind kind);
		void adr(ArmV8Register dst, int64_t imm);
		void adrp(ArmV8Register dst, int64_t imm);
		void add(ArmV8Register dst, ArmV8Register src, uint16_t imm);
		void b(uint32_t imm);
		void b(std::string const& label);
		void bl(uint32_t imm);
		void br(ArmV8Register reg);
		void blr(ArmV8Register reg);
		void nop();

		void ldr(ArmV8Register dst, ArmV8Register src, int32_t imm);
		void ldr(ArmV8Register dst, int32_t literal);

		void tbz(ArmV8Register reg, int32_t bit, int32_t imm);
		void tbnz(ArmV8Register reg, int32_t bit, int32_t imm);

		/* Pseudo instructions */

		void push(ArmV8RegisterArray const& array);
		void pop(ArmV8RegisterArray const& array);
	};
	
}