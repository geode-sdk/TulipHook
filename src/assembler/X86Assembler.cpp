#include "X86Assembler.hpp"

using namespace tulip::hook;

// register index, even if its xmm
uint8_t regIdx(X86Register reg) {
	if (reg > X86Register::XMM0) {
		return static_cast<uint8_t>(reg) - static_cast<uint8_t>(X86Register::XMM0);
	}
	return static_cast<uint8_t>(reg);
}

X86Assembler::X86Assembler(uint64_t baseAddress) :
	BaseAssembler(baseAddress) {}

X86Assembler::~X86Assembler() {}

void X86Assembler::label32(std::string const& name) {
	m_labelUpdates.push_back({this->currentAddress(), name, 4});
	this->write32(0);
}

void X86Assembler::updateLabels() {
	for (auto const& update : m_labelUpdates) {
		this->rewrite32(update.m_address, m_labels[update.m_name]);
	}
}

void X86Assembler::nop() {
	this->write8(0x90);
}

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

static void encodeModRM(X86Assembler* ass, X86Operand op, uint8_t digit) {
	if (op.m_type == X86Operand::Type::Register) {
		ass->write8((0b11 << 6) | (digit << 3) | regIdx(op.m_reg));
	}
	else if (op.m_type == X86Operand::Type::ModRM) {
		// the two mod bits
		uint8_t mod;
		// [ebp] is forced to be [ebp + 0]
		if (op.m_value || op.m_reg == X86Register::EBP) {
			mod = op.m_value <= 0xff ? 0b01 : 0b10;
		}
		else {
			mod = 0b00;
		}

		ass->write8((mod << 6) | (digit << 3) | regIdx(op.m_reg));
		if (op.m_reg == X86Register::ESP) {
			// this extra byte is used to represent scaled registers,
			// however we dont use those, so we only need it for esp
			ass->write8(0x24);
		}

		if (mod == 0b01) {
			ass->write8(op.m_value);
		}
		else if (mod == 0b10) {
			ass->write32(op.m_value);
		}
	}
}

void X86Assembler::add(X86Register reg, uint32_t value) {
	this->write8(0x81);
	this->write8(0xC0 | regIdx(reg));
	this->write32(value);
}

void X86Assembler::sub(X86Register reg, uint32_t value) {
	this->write8(0x81);
	this->write8(0xE8 | regIdx(reg));
	this->write32(value);
}

void X86Assembler::push(X86Register reg) {
	this->write8(0x50 | regIdx(reg));
}

void X86Assembler::push(X86Pointer reg) {
	this->write8(0xFF);
	encodeModRM(this, reg, 6);
}

void X86Assembler::pop(X86Register reg) {
	this->write8(0x58 | regIdx(reg));
}

void X86Assembler::jmp(X86Register reg) {
	this->write8(0xFF);
	encodeModRM(this, reg, 4);
}

void X86Assembler::jmp(uint64_t address) {
	this->write8(0xE9);
	// typical formula is target - addr - 5,
	// but add + 1 because we just wrote one byte
	this->write32(address - this->currentAddress() - 5 + 1);
}

void X86Assembler::call(X86Register reg) {
	this->write8(0xFF);
	this->write8(0xD0 | regIdx(reg));
}

void X86Assembler::movsd(X86Register reg, X86Pointer ptr) {
	this->write8(0xF2);
	this->write8(0x0F);
	this->write8(0x10);
	encodeModRM(this, ptr, regIdx(reg));
}

void X86Assembler::movsd(X86Pointer ptr, X86Register reg) {
	this->write8(0xF2);
	this->write8(0x0F);
	this->write8(0x11);
	encodeModRM(this, ptr, regIdx(reg));
}

void X86Assembler::movss(X86Register reg, X86Pointer ptr) {
	this->write8(0xF3);
	this->write8(0x0F);
	this->write8(0x10);
	encodeModRM(this, ptr, regIdx(reg));
}

void X86Assembler::movss(X86Pointer ptr, X86Register reg) {
	this->write8(0xF3);
	this->write8(0x0F);
	this->write8(0x11);
	encodeModRM(this, ptr, regIdx(reg));
}

void X86Assembler::movaps(X86Register reg, X86Pointer ptr) {
	this->write8(0x0F);
	this->write8(0x28);
	encodeModRM(this, ptr, regIdx(reg));
}

void X86Assembler::movaps(X86Pointer ptr, X86Register reg) {
	this->write8(0x0F);
	this->write8(0x29);
	encodeModRM(this, ptr, regIdx(reg));
}

void X86Assembler::lea(X86Register reg, std::string const& label) {
	this->write8(0x8D);
	this->write8(0x05 | regIdx(reg) << 3);
	this->label32(label);
}

void X86Assembler::mov(X86Register reg, uint32_t value) {
	this->write8(0xB8 | regIdx(reg));
	this->write32(value);
}

void X86Assembler::mov(X86Register reg, X86Pointer ptr) {
	this->write8(0x8B);
	encodeModRM(this, ptr, regIdx(reg));
}

void X86Assembler::mov(X86Pointer ptr, X86Register reg) {
	this->write8(0x89);
	encodeModRM(this, ptr, regIdx(reg));
}

void X86Assembler::mov(X86Register dst, X86Register src) {
	this->write8(0x89);
	encodeModRM(this, dst, regIdx(src));
}

void X86Assembler::mov(X86Register reg, std::string const& label) {
	this->write8(0x8B);
	this->write8(0x05 | regIdx(reg) << 3);
	this->label32(label);
}
