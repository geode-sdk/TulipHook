#include "../src/assembler/X86Assembler.hpp"
#include "Assembler.hpp"

#include <gtest/gtest.h>

using namespace tulip::hook;

using enum X86Register;
static RegMem32 m;

TEST(X86AssemblerTest, NopMov) {
	X86Assembler a(0x123);
	a.nop();
	a.mov(EAX, 10);
	EXPECT_EQ(a.buffer(), "\x90\xb8\x0a\x00\x00\x00"_bytes);
}

TEST(X86AssemblerTest, JmpCall) {
	X86Assembler a(0x123);
	a.jmp(0xb00b5);
	a.jmp(ECX);
	a.call(EAX);
	a.call(EBP);
	a.call(ESP);
	EXPECT_EQ(a.buffer(), "\xE9\x8D\xFF\x0A\x00\xFF\xE1\xFF\xD0\xFF\xD5\xFF\xD4"_bytes);
}

TEST(X86AssemblerTest, DirectCall) {
	X86Assembler a(0);
	a.call(0x456);
	EXPECT_EQ(a.buffer(), "\xE8\x51\x04\x00\x00"_bytes);
}

TEST(X86AssemblerTest, Push) {
	X86Assembler a(0x123);
	a.push(EAX);
	a.push(ESP);
	a.push(m[ESP + 0x10]);
	EXPECT_EQ(a.buffer(), "\x50\x54\xFF\x74\x24\x10"_bytes);
}

TEST(X86AssemblerTest, Mov) {
	X86Assembler a(0x123);
	a.mov(EAX, EAX);
	a.mov(ECX, EAX);
	a.mov(ECX, m[EDX + 4]);
	a.mov(ECX, m[EBP + 4]);
	a.mov(m[EBP + 4], ESP);
	a.mov(m[EBP], EAX);
	EXPECT_EQ(a.buffer(), "\x89\xC0\x89\xC1\x8B\x4A\x04\x8B\x4D\x04\x89\x65\x04\x89\x45\x00"_bytes);
}

TEST(X86AssemblerTest, Movsd) {
	X86Assembler a(0x123);
	a.movsd(m[ESP], XMM0);
	a.movsd(XMM1, m[ESP + 4]);
	EXPECT_EQ(a.buffer(), "\xF2\x0F\x11\x04\x24\xF2\x0F\x10\x4C\x24\x04"_bytes);
}

TEST(X86AssemblerTest, Movss) {
	X86Assembler a(0x123);
	a.movss(m[ESP], XMM0);
	a.movss(XMM1, m[ESP + 4]);
	EXPECT_EQ(a.buffer(), "\xF3\x0F\x11\x04\x24\xF3\x0F\x10\x4C\x24\x04"_bytes);
}

TEST(X86AssemblerTest, Movaps) {
	X86Assembler a(0x123);
	a.movaps(m[ESP], XMM0);
	a.movaps(XMM1, m[ESP + 4]);
	EXPECT_EQ(a.buffer(), "\x0F\x29\x04\x24\x0F\x28\x4C\x24\x04"_bytes);
}

TEST(X86AssemblerTest, Label) {
	X86Assembler a(0x123);
	a.mov(EAX, "label");
	a.lea(ECX, "label");
	a.label("label");
	a.write32(0x80085);
	a.updateLabels();
	EXPECT_EQ(a.buffer(), "\x8B\x05\x2f\x01\x00\x00\x8D\x0D\x2f\x01\x00\x00\x85\x00\x08\x00"_bytes);
}