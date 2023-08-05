#include <gtest/gtest.h>

#include "../src/assembler/X86Assembler.hpp"

using namespace tulip::hook;

std::vector<uint8_t> operator""_bytes(const char* data, size_t size) {
	return {reinterpret_cast<const uint8_t*>(data), reinterpret_cast<const uint8_t*>(data + size)};
}

TEST(X86AssemblerTest, NopMov) {
	using enum X86Register;
	X86Assembler a(0x123);
	a.nop();
	a.mov(EAX, 10);
	EXPECT_EQ(a.buffer(), "\x90\xb8\x0a\x00\x00\x00"_bytes);
}

TEST(X86AssemblerTest, JmpCall) {
	using enum X86Register;
	X86Assembler a(0x123);
	a.jmp(0xb00b5);
	a.jmp(ECX);
	a.call(EAX);
	a.call(EBP);
	a.call(ESP);
	EXPECT_EQ(a.buffer(), "\xE9\x8D\xFF\x0A\x00\xFF\xE1\xFF\xD0\xFF\xD5\xFF\xD4"_bytes);
}

TEST(X86AssemblerTest, Push) {
	using enum X86Register;
	X86Assembler a(0x123);
	RegMem32 m;
	a.push(EAX);
	a.push(ESP);
	a.push(m[ESP + 0x10]);
	EXPECT_EQ(a.buffer(), "\x50\x54\xFF\x74\x24\x10"_bytes);
}

TEST(X86AssemblerTest, Mov) {
	using enum X86Register;
	X86Assembler a(0x123);
	RegMem32 m;
	a.mov(EAX, EAX);
	a.mov(ECX, EAX);
	a.mov(ECX, m[EDX + 4]);
	a.mov(ECX, m[EBP + 4]);
	a.mov(m[EBP + 4], ESP);
	a.mov(m[EBP], EAX);
	EXPECT_EQ(a.buffer(), "\x89\xC0\x89\xC1\x8B\x4A\x04\x8B\x4D\x04\x89\x65\x04\x89\x45\x00"_bytes);
}

TEST(X86AssemblerTest, Movsd) {
	using enum X86Register;
	X86Assembler a(0x123);
	RegMem32 m;
	a.movsd(m[ESP], XMM0);
	a.movsd(XMM1, m[ESP + 4]);
	EXPECT_EQ(a.buffer(), "\xF2\x0F\x11\x04\x24\xF2\x0F\x10\x4C\x24\x04"_bytes);
}

TEST(X86AssemblerTest, Movss) {
	using enum X86Register;
	X86Assembler a(0x123);
	RegMem32 m;
	a.movss(m[ESP], XMM0);
	a.movss(XMM1, m[ESP + 4]);
	EXPECT_EQ(a.buffer(), "\xF3\x0F\x11\x04\x24\xF3\x0F\x10\x4C\x24\x04"_bytes);
}
