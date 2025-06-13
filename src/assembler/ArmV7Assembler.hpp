#pragma once

#include "ThumbV7Assembler.hpp"

namespace tulip::hook {
	class ArmV7Assembler : public BaseAssembler {
	public:
		ArmV7Assembler(int64_t baseAddress);
		ArmV7Assembler(ArmV7Assembler const&) = delete;
		ArmV7Assembler(ArmV7Assembler&&) = delete;
		~ArmV7Assembler();

		virtual uint8_t* lastInsn();
		void rwl(int8_t offset, int8_t size, int32_t value);
        
		void ldr(ArmV7Register dst, ArmV7Register src, int32_t offset);
	};
}