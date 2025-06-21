#include "../src/assembler/X64Assembler.hpp"
#include "Assembler.hpp"

#include <gtest/gtest.h>

using namespace tulip::hook;

using enum X64Register;
static RegMem64 m;

TEST(X64AssemblerTest, Nop) {
    X64Assembler a(0x123);
    a.nop();
    EXPECT_EQ(a.buffer(), "\x90"_bytes);
}

TEST(X64AssemblerTest, Jmp) {
    X64Assembler a(0x123);
    a.jmp(0xb00b5);
    a.jmp(RCX);
    a.jmp(R8);
    a.jmp(0x123);
    EXPECT_EQ(a.buffer(), "\xE9\x8D\xFF\x0A\x00\xFF\xE1\x41\xFF\xE0\xEB\xF4"_bytes);
}

TEST(X64AssemblerTest, Jmp8) {
    X64Assembler a(0x123);
    a.jmp8("label");
    a.write32(0x80085);
    a.label("label");
    a.updateLabels();
    EXPECT_EQ(a.buffer(), "\xEB\x04\x85\x00\x08\x00"_bytes);
}

TEST(X64AssemblerTest, Call) {
    X64Assembler a(0x123);
    a.call(R13);
    a.call(RSP);
    EXPECT_EQ(a.buffer(), "\x41\xFF\xD5\xFF\xD4"_bytes);
}

TEST(X64AssemblerTest, Push) {
    X64Assembler a(0x123);
    a.push(RAX);
    a.push(R12);
    a.push(m[RSP + 0x10]);
    EXPECT_EQ(a.buffer(), "\x50\x41\x54\xFF\x74\x24\x10"_bytes);
}

TEST(X64AssemblerTest, Mov) {
    X64Assembler a(0x123);
    a.mov(R8, 10);
    a.mov(RAX, RAX);
    a.mov(R9, R8);
    a.mov(RCX, m[R10 + 4]);
    a.mov(R9, m[RBP + 4]);
    a.mov(m[RBP + 4], RSP);
    a.mov(m[R13], R8);
    EXPECT_EQ(
        a.buffer(),
        "\x49\xc7\xc0\x0a\x00\x00\x00\x48\x89\xC0\x4D\x89\xC1\x49\x8B\x4A\x04\x4C\x8B\x4D\x04\x48\x89\x65\x04\x4D\x89\x45\x00"_bytes
    );
}

TEST(X64AssemblerTest, Movsd) {
    X64Assembler a(0x123);
    a.movsd(m[RSP], XMM0);
    a.movsd(XMM1, m[RSP + 4]);
    EXPECT_EQ(a.buffer(), "\xF2\x0F\x11\x04\x24\xF2\x0F\x10\x4C\x24\x04"_bytes);
}

TEST(X64AssemblerTest, Movss) {
    X64Assembler a(0x123);
    a.movss(m[RSP], XMM0);
    a.movss(XMM1, m[RSP + 4]);
    EXPECT_EQ(a.buffer(), "\xF3\x0F\x11\x04\x24\xF3\x0F\x10\x4C\x24\x04"_bytes);
}

TEST(X64AssemblerTest, Movaps) {
    X64Assembler a(0x123);
    a.movaps(m[RSP], XMM0);
    a.movaps(XMM1, m[RSP + 4]);
    EXPECT_EQ(a.buffer(), "\x0F\x29\x04\x24\x0F\x28\x4C\x24\x04"_bytes);
}

TEST(X64AssemblerTest, Label) {
    X64Assembler a(0x123);
    a.mov(RAX, "label");
    a.lea(RCX, "label");
    a.label("label");
    a.write64(0x80085);
    a.updateLabels();
    EXPECT_EQ(
        a.buffer(), "\x48\x8B\x05\x07\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\x85\x00\x08\x00\x00\x00\x00\x00"_bytes
    );
}

TEST(X64AssemblerTest, Xchg) {
    X64Assembler a(0x123);
    a.xchg(RCX, RDX);
    a.xchg(RBX, R8);
    EXPECT_EQ(a.buffer(), "\x48\x87\xD1\x4C\x87\xC3"_bytes);
}