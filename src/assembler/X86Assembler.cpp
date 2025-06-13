#include "X86Assembler.hpp"

using namespace tulip::hook;

// register index, even if its xmm
uint8_t regIdx(X86Register reg) {
	if (reg > X86Register::XMM0) {
		return static_cast<uint8_t>(reg) - static_cast<uint8_t>(X86Register::XMM0);
	}
	return static_cast<uint8_t>(reg);
}

X86Assembler::X86Assembler(int64_t baseAddress) :
	BaseAssembler(baseAddress) {}

X86Assembler::~X86Assembler() {}

void X86Assembler::label8(std::string const& name) {
	m_labelUpdates.push_back({this->currentAddress(), name, 1, 0});
	this->write8(0);
}

void X86Assembler::label32(std::string const& name) {
	m_labelUpdates.push_back({this->currentAddress(), name, 4, 0});
	this->write32(0);
}

void X86Assembler::abslabel32(std::string const& name) {
	m_absoluteLabelUpdates.push_back({this->currentAddress(), name, 4, 0});
	this->write32(0);
}

void X86Assembler::updateLabels() {
	for (auto const& update : m_labelUpdates) {
		if (update.m_size == 4) this->rewrite32(update.m_address, m_labels[update.m_name] - update.m_address - 4);
		else if (update.m_size == 1) this->rewrite8(update.m_address, m_labels[update.m_name] - update.m_address - 1);
	}
	for (auto const& update : m_absoluteLabelUpdates) {
		this->rewrite32(update.m_address, m_labels[update.m_name]);
	}
}

void X86Assembler::nop() {
	this->write8(0x90);
}

void X86Assembler::int3() {
	this->write8(0xCC);
}

void X86Assembler::ret() {
	this->write8(0xC3);
}

void X86Assembler::ret(int16_t offset) {
	this->write8(0xC2);
	this->write16(offset);
}

void X86Assembler::encodeModRM(X86Operand op, uint8_t digit) {
	if (op.m_type == X86Operand::Type::Register) {
		this->write8((0b11 << 6) | (digit << 3) | regIdx(op.m_reg));
	}
	else if (op.m_type == X86Operand::Type::ModRM) {
		// the two mod bits
		uint8_t mod;
		// [ebp] is forced to be [ebp + 0]
		if (op.m_value || op.m_reg == X86Register::EBP) {
			mod = op.m_value <= 0x7f && op.m_value >= -0x80 ? 0b01 : 0b10;
		}
		else {
			mod = 0b00;
		}

		this->write8((mod << 6) | (digit << 3) | regIdx(op.m_reg));
		if (op.m_reg == X86Register::ESP) {
			// this extra byte is used to represent scaled registers,
			// however we dont use those, so we only need it for esp
			this->write8(0x24);
		}

		if (mod == 0b01) {
			this->write8(op.m_value);
		}
		else if (mod == 0b10) {
			this->write32(op.m_value);
		}
	}
}

void X86Assembler::add(X86Register reg, int32_t value) {
	if (value >= -0x80 && value <= 0x7f) {
		this->write8(0x83);
		this->write8(0xC0 | regIdx(reg));
		this->write8(value);
	}
	else {
		this->write8(0x81);
		this->write8(0xC0 | regIdx(reg));
		this->write32(value);
	}
}

void X86Assembler::sub(X86Register reg, int32_t value) {
	if (value >= -0x80 && value <= 0x7f) {
		this->write8(0x83);
		this->write8(0xE8 | regIdx(reg));
		this->write8(value);
	}
	else {
		this->write8(0x81);
		this->write8(0xE8 | regIdx(reg));
		this->write32(value);
	}
}

void X86Assembler::push(X86Register reg) {
	this->write8(0x50 | regIdx(reg));
}

void X86Assembler::push(X86Pointer reg) {
	this->write8(0xFF);
	this->encodeModRM(reg, 6);
}

void X86Assembler::pop(X86Register reg) {
	this->write8(0x58 | regIdx(reg));
}

void X86Assembler::jmp(X86Register reg) {
	this->write8(0xFF);
	this->encodeModRM(reg, 4);
}

void X86Assembler::jmp(int64_t address) {
	auto const difference = address - this->currentAddress();
	if (difference - 2 >= -0x80 && difference - 2 <= 0x7f) {
		this->write8(0xEB);
		this->write8(difference - 2);
	}
	else {
		// typical formula is target - addr - 5,
		this->write8(0xE9);
		this->write32(difference - 5);
	}
}

void X86Assembler::jmp(std::string const& label) {
	this->write8(0xE9);
	this->label32(label);
}

void X86Assembler::jmp8(std::string const& label) {
	this->write8(0xEB);
	this->label8(label);
}

void X86Assembler::call(int64_t address) {
	this->write8(0xE8);
	// typical formula is target - addr - 5,
	// but add + 1 because we just wrote one byte
	this->write32(address - this->currentAddress() - 5 + 1);
}

void X86Assembler::call(X86Register reg) {
	this->write8(0xFF);
	this->encodeModRM(reg, 2);
}

void X86Assembler::call(std::string const& label) {
	this->write8(0xE8);
	this->label32(label);
}

void X86Assembler::movsd(X86Register reg, X86Pointer ptr) {
	this->write8(0xF2);
	this->write8(0x0F);
	this->write8(0x10);
	this->encodeModRM(ptr, regIdx(reg));
}

void X86Assembler::movsd(X86Pointer ptr, X86Register reg) {
	this->write8(0xF2);
	this->write8(0x0F);
	this->write8(0x11);
	this->encodeModRM(ptr, regIdx(reg));
}

void X86Assembler::movss(X86Register reg, X86Pointer ptr) {
	this->write8(0xF3);
	this->write8(0x0F);
	this->write8(0x10);
	this->encodeModRM(ptr, regIdx(reg));
}

void X86Assembler::movss(X86Pointer ptr, X86Register reg) {
	this->write8(0xF3);
	this->write8(0x0F);
	this->write8(0x11);
	this->encodeModRM(ptr, regIdx(reg));
}

void X86Assembler::movaps(X86Register reg, X86Pointer ptr) {
	this->write8(0x0F);
	this->write8(0x28);
	this->encodeModRM(ptr, regIdx(reg));
}

void X86Assembler::movaps(X86Pointer ptr, X86Register reg) {
	this->write8(0x0F);
	this->write8(0x29);
	this->encodeModRM(ptr, regIdx(reg));
}

void X86Assembler::lea(X86Register reg, std::string const& label) {
	this->write8(0x8D);
	this->write8(0x05 | regIdx(reg) << 3);
	this->abslabel32(label);
}

void X86Assembler::mov(X86Register reg, int32_t value) {
	this->write8(0xB8 | regIdx(reg));
	this->write32(value);
}

void X86Assembler::mov(X86Register reg, X86Pointer ptr) {
	this->write8(0x8B);
	this->encodeModRM(ptr, regIdx(reg));
}

void X86Assembler::mov(X86Pointer ptr, X86Register reg) {
	this->write8(0x89);
	this->encodeModRM(ptr, regIdx(reg));
}

void X86Assembler::mov(X86Register dst, X86Register src) {
	this->write8(0x89);
	this->encodeModRM(dst, regIdx(src));
}

void X86Assembler::mov(X86Register reg, std::string const& label) {
	this->write8(0x8B);
	this->write8(0x05 | regIdx(reg) << 3);
	this->abslabel32(label);
}

void X86Assembler::fstps(X86Pointer ptr) {
	// 32 bit fstp
	this->write8(0xD9);
	this->encodeModRM(ptr, 3);
}
void X86Assembler::flds(X86Pointer ptr) {
	// 32 bit fld
	this->write8(0xD9);
	this->encodeModRM(ptr, 0);
}
void X86Assembler::fstpd(X86Pointer ptr) {
	// 64 bit fstp
	this->write8(0xDD);
	this->encodeModRM(ptr, 3);
}
void X86Assembler::fldd(X86Pointer ptr) {
	// 64 bit fld
	this->write8(0xDD);
	this->encodeModRM(ptr, 0);
}

void X86Assembler::shr(X86Register reg, uint8_t value) {
	this->write8(0xC1);
	this->write8(0xE8 | regIdx(reg));
	this->write8(value);
}

void X86Assembler::shl(X86Register reg, uint8_t value) {
	this->write8(0xC1);
	this->write8(0xE0 | regIdx(reg));
	this->write8(value);
}

void X86Assembler::xchg(X86Register reg, X86Register reg2) {
	this->write8(0x87);
	this->encodeModRM(reg, regIdx(reg2));
}

void X86Assembler::cmp(X86Register reg, X86Register reg2) {
	this->write8(0x39);
	this->encodeModRM(reg, regIdx(reg2));
}
void X86Assembler::cmp(X86Register reg, int32_t value) {
	if (value >= -0x80 && value <= 0x7f) {
		this->write8(0x83);
		this->write8(0xf8 | regIdx(reg));
		this->write8(value);
	}
	else {
		this->write8(0x81);
		this->write8(0xf8 | regIdx(reg));
		this->write32(value);
	}
}

void X86Assembler::align16() {
	auto align = 16 - (this->currentAddress() % 16);
	for (auto i = 0; i < align; i++) {
		this->write8(0x90);
	}
}