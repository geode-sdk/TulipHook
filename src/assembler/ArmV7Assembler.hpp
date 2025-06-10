#pragma once

#include "BaseAssembler.hpp"

namespace tulip::hook {

	// there are more but idc
	enum class ArmV7Register : uint8_t {
		R0 = 0x0,
		R1,
		R2,
		R3,
		R4,
		R5,
		R6,
		R7,
		R8,
		R9,
		R10,
		R11,
		R12,
		SP,
		LR,
		PC,
		D0 = 0x40,
		D1,
		D2,
		D3,
		D4,
		D5,
		D6,
		D7,
	};

	using ArmV7RegisterArray = std::vector<ArmV7Register>;

	class TULIP_HOOK_DLL ArmV7Assembler : public BaseAssembler {
	public:
		ArmV7Assembler(int64_t baseAddress);
		ArmV7Assembler(ArmV7Assembler const&) = delete;
		ArmV7Assembler(ArmV7Assembler&&) = delete;
		~ArmV7Assembler();

		virtual uint8_t* lastInsn();
		void rwl(int8_t offset, int8_t size, int32_t value);

		void label8(std::string const& name);
		void updateLabels() override;

		void nop();

		void push(ArmV7RegisterArray const& array);
		void vpush(ArmV7RegisterArray const& array);

		void pop(ArmV7RegisterArray const& array);
		void vpop(ArmV7RegisterArray const& array);

		void ldr(ArmV7Register dst, std::string const& label);

		// ldr.w pc, [pc, #-0x4]
		// i cant bother to do stuff
		void ldrpcn();

		// non thumb version
		void ldrpcn2();

		void mov(ArmV7Register dst, ArmV7Register src);

		void blx(ArmV7Register dst);
		void bx(ArmV7Register src);
	};
}