#pragma once

#include "X86Assembler.hpp"

namespace tulip::hook {

	enum class X64Register : uint8_t {
		RAX = 0x0,
		RCX,
		RDX,
		RBX,
		RSP,
		RBP,
		RSI,
		RDI,
		R8,
		R9,
		R10,
		R11,
		R12,
		R13,
		R14,
		R15,
		XMM0 = 0x80,
		XMM1,
		XMM2,
		XMM3,
		XMM4,
		XMM5,
		XMM6,
		XMM7
	};

	struct X64Pointer {
		X64Register reg;
		int32_t offset = 0;

		X64Pointer(X64Register reg, int32_t offset = 0) :
			reg(reg),
			offset(offset) {}
	};

	inline X64Pointer operator+(X64Register reg, int32_t offset) {
		return X64Pointer(reg, offset);
	}

	// Use this to easily express a X64Pointer, like so:
	// RegMem32 m;
	// m[RSP], m[RSP + 4]
	struct RegMem64 {
		X64Pointer operator[](X64Pointer ptr) {
			return ptr;
		}
	};

	class X64Assembler : public X86Assembler {
	public:
		X64Assembler(uint64_t baseAddress);
		X64Assembler(X64Assembler const&) = delete;
		X64Assembler(X64Assembler&&) = delete;
		~X64Assembler();

		void updateLabels() override;

		void nop();

		void add(X64Register reg, uint32_t value);
		void sub(X64Register reg, uint32_t value);

		void push(X64Register reg);
		void push(X64Pointer ptr);
		void pop(X64Register reg);

		void jmp(X64Register reg);
		void jmp(uint64_t address);

		void call(X64Register reg);

		void movsd(X64Register reg, X64Pointer ptr);
		void movsd(X64Pointer ptr, X64Register reg);

		void movss(X64Register reg, X64Pointer ptr);
		void movss(X64Pointer ptr, X64Register reg);

		void movaps(X64Register reg, X64Pointer ptr);
		void movaps(X64Pointer ptr, X64Register reg);

		void lea(X64Register reg, std::string const& label);

		void mov(X64Register reg, uint32_t value);
		void mov(X64Register reg, X64Pointer ptr);
		void mov(X64Pointer ptr, X64Register reg);
		void mov(X64Register reg, X64Register reg2);
		void mov(X64Register reg, std::string const& label);
	};
}