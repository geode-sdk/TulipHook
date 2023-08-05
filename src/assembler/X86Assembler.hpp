#pragma once

#include "BaseAssembler.hpp"

namespace tulip::hook {

	enum class X86Register : uint8_t {
		EAX = 0x0,
		ECX,
		EDX,
		EBX,
		ESP,
		EBP,
		ESI,
		EDI,
		XMM0 = 0x80,
		XMM1,
		XMM2,
		XMM3,
		XMM4,
		XMM5,
		XMM6,
		XMM7
	};

	struct X86Pointer {
		X86Register reg;
		int32_t offset = 0;

		X86Pointer(X86Register reg, int32_t offset = 0) :
			reg(reg),
			offset(offset) {}
	};

	inline X86Pointer operator+(X86Register reg, int32_t offset) {
		return X86Pointer(reg, offset);
	}

	// Use this to easily express a X86Pointer, like so:
	// RegMem32 m;
	// m[ESP], m[ESP + 4]
	struct RegMem32 {
		X86Pointer operator[](X86Pointer ptr) {
			return ptr;
		}
	};

	struct X86Operand {
		enum class Type {
			Register,
			ModRM,
		} m_type;
		X86Register m_reg;
		uint32_t m_value = 0;

		X86Operand(X86Register reg) :
			m_reg(reg),
			m_type(Type::Register) {}

		X86Operand(X86Pointer ptr) :
			m_reg(ptr.reg),
			m_value(ptr.offset),
			m_type(Type::ModRM) {}
	};

	class X86Assembler : public BaseAssembler {
	protected:
		void encodeModRM(X86Operand op, uint8_t digit);

	public:
		X86Assembler(uint64_t baseAddress);
		X86Assembler(X86Assembler const&) = delete;
		X86Assembler(X86Assembler&&) = delete;
		~X86Assembler();

		void label32(std::string const& name);
		void updateLabels() override;

		void nop();

		void ret();
		void ret(uint16_t offset);

		void add(X86Register reg, uint32_t value);
		void sub(X86Register reg, uint32_t value);

		void push(X86Register reg);
		void push(X86Pointer reg);
		void pop(X86Register reg);

		void jmp(X86Register reg);
		void jmp(uint64_t address);

		void call(X86Register reg);

		void movsd(X86Register reg, X86Pointer ptr);
		void movsd(X86Pointer ptr, X86Register reg);

		void movss(X86Register reg, X86Pointer ptr);
		void movss(X86Pointer ptr, X86Register reg);

		void movaps(X86Register reg, X86Pointer ptr);
		void movaps(X86Pointer ptr, X86Register reg);

		void lea(X86Register reg, std::string const& label);

		void mov(X86Register reg, uint32_t value);
		void mov(X86Register reg, X86Pointer ptr);
		void mov(X86Pointer ptr, X86Register reg);
		void mov(X86Register reg, X86Register reg2);
		void mov(X86Register reg, std::string const& label);
	};
}