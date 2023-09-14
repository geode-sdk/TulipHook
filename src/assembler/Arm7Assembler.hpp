#pragma once

#include "BaseAssembler.hpp"

namespace tulip::hook {

	// there are more but idc
	enum class Arm7Register : uint8_t {
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

	using Arm7RegisterArray = std::vector<Arm7Register>;

	class Arm7Assembler : public BaseAssembler {
	public:
		Arm7Assembler(int64_t baseAddress);
		Arm7Assembler(Arm7Assembler const&) = delete;
		Arm7Assembler(Arm7Assembler&&) = delete;
		~Arm7Assembler();

		virtual uint8_t* lastInsn();
		void rwl(int8_t offset, int8_t size, int32_t value);

		void label8(std::string const& name);
		void updateLabels() override;

		void nop();

		void push(Arm7RegisterArray const& array);
		void vpush(Arm7RegisterArray const& array);

		void pop(Arm7RegisterArray const& array);
		void vpop(Arm7RegisterArray const& array);

		void ldr(Arm7Register dst, std::string const& label);
		void ldrw(Arm7Register dst, std::string const& label);

		void mov(Arm7Register dst, Arm7Register src);

		void blx(Arm7Register dst);
		void bx(Arm7Register src);
	};
}