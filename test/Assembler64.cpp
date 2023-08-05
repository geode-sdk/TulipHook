#include "../src/assembler/X64Assembler.hpp"
#include "Assembler.hpp"

#include <gtest/gtest.h>

using namespace tulip::hook;

TEST(X64AssemblerTest, NopMov) {
	using enum X64Register;
	X64Assembler a(0x123);
	a.nop();
	a.mov(R8, 10);
	EXPECT_EQ(a.buffer(), "\x90\x49\xc7\xc0\x0a\x00\x00\x00"_bytes);
}

TEST(X64AssemblerTest, JmpCall) {
	using enum X64Register;
	X64Assembler a(0x123);
	a.jmp(0xb00b5);
	a.jmp(RCX);
	a.jmp(R8);
	a.call(R13);
	a.call(RSP);
	EXPECT_EQ(a.buffer(), "\xE9\x8D\xFF\x0A\x00\xFF\xE1\x41\xFF\xE0\x41\xFF\xD5\xFF\xD4"_bytes);
}

TEST(X64AssemblerTest, Push) {
	using enum X64Register;
	X64Assembler a(0x123);
	RegMem64 m;
	a.push(RAX);
	a.push(R12);
	a.push(m[RSP + 0x10]);
	EXPECT_EQ(a.buffer(), "\x50\x41\x54\xFF\x74\x24\x10"_bytes);
}

TEST(X64AssemblerTest, Mov) {
	using enum X64Register;
	X64Assembler a(0x123);
	RegMem64 m;
	a.mov(RAX, RAX);
	a.mov(R9, R8);
	a.mov(RCX, m[R10 + 4]);
	a.mov(R9, m[RBP + 4]);
	a.mov(m[RBP + 4], RSP);
	a.mov(m[R13], R8);
	EXPECT_EQ(
		a.buffer(), "\x48\x89\xC0\x4D\x89\xC1\x49\x8B\x4A\x04\x4C\x8B\x4D\x04\x48\x89\x65\x04\x4D\x89\x45\x00"_bytes
	);
}

TEST(X64AssemblerTest, Movsd) {
	using enum X64Register;
	X64Assembler a(0x123);
	RegMem64 m;
	a.movsd(m[RSP], XMM0);
	a.movsd(XMM1, m[RSP + 4]);
	EXPECT_EQ(a.buffer(), "\xF2\x0F\x11\x04\x24\xF2\x0F\x10\x4C\x24\x04"_bytes);
}

TEST(X64AssemblerTest, Movss) {
	using enum X64Register;
	X64Assembler a(0x123);
	RegMem64 m;
	a.movss(m[RSP], XMM0);
	a.movss(XMM1, m[RSP + 4]);
	EXPECT_EQ(a.buffer(), "\xF3\x0F\x11\x04\x24\xF3\x0F\x10\x4C\x24\x04"_bytes);
}

TEST(X64AssemblerTest, Movaps) {
	using enum X64Register;
	X64Assembler a(0x123);
	RegMem64 m;
	a.movaps(m[RSP], XMM0);
	a.movaps(XMM1, m[RSP + 4]);
	EXPECT_EQ(a.buffer(), "\x0F\x29\x04\x24\x0F\x28\x4C\x24\x04"_bytes);
}
