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
	};

	class ArmV8Assembler : public BaseAssembler {
	public:
		using BaseAssembler::BaseAssembler;
	};
	
}