#pragma once

#include "BaseAssembler.hpp"

namespace tulip::hook {

	// there are more but idc
	enum class ArmRegister : uint8_t {
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

	using ArmRegisterArray = std::vector<ArmRegister>;

	class ArmThumbAssembler : public BaseAssembler {
	public:
		ArmThumbAssembler(int64_t baseAddress);
		ArmThumbAssembler(ArmThumbAssembler const&) = delete;
		ArmThumbAssembler(ArmThumbAssembler&&) = delete;
		~ArmThumbAssembler();

		virtual uint8_t* lastInsn();
		void rwl(int8_t offset, int8_t size, int32_t value);

		void label8(std::string const& name);
		void updateLabels() override;

		void nop();

		void push(ArmRegisterArray const& array);
		void vpush(ArmRegisterArray const& array);

		void pop(ArmRegisterArray const& array);
		void vpop(ArmRegisterArray const& array);

		void ldr(ArmRegister dst, std::string const& label);
		void ldrw(ArmRegister dst, std::string const& label);

		void mov(ArmRegister dst, ArmRegister src);

		void blx(ArmRegister dst);
		void bx(ArmRegister src);
	};
}