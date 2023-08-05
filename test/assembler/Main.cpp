#include <tulip/TulipHook.hpp>
#include "../../src/assembler/X86Assembler.hpp"
#include <iostream>
#include <iomanip>

using namespace tulip::hook;

std::vector<uint8_t> operator""_bytes(const char* data, size_t size) {
    return std::vector(reinterpret_cast<const uint8_t*>(data), reinterpret_cast<const uint8_t*>(data + size));
}

std::ostream& operator<<(std::ostream& stream, const std::vector<uint8_t>& value) {
    stream << '{';
    bool first = true;
    for (const auto& x : value) {
        if (!first)
            stream << ' ';
        first = false;
        stream << std::hex << std::setw(2) << std::setfill('0') << int(x);
    }
    return stream << '}';
}

template <class T, class U>
void assertEqImpl(T&& a, U&& b, const char* expr, const char* file, int line) {
    if (a != b) {
        std::cout << "Assertion `" << expr << "` failed at " << file << ':' << line << std::endl;
        std::cout << "lhs is: " << a << std::endl;
        std::cout << "rhs is: " << b << std::endl;
        std::abort();
    }
}

#define assertEq(a, b) assertEqImpl(a, b, #a " == " #b, __FILE__, __LINE__)

int main() {
    using enum X86Register;
    RegMem32 m;

    {
        X86Assembler a(0x123);
        a.nop();
        a.mov(EAX, 10);
        assertEq(a.buffer(), "\x90\xb8\x0a\x00\x00\x00"_bytes);
    }

    {
        X86Assembler a(0x123);
        a.jmp(0xb00b5);
        a.jmp(ECX);
        a.call(EAX);
        a.call(EBP);
        a.call(ESP);
        assertEq(a.buffer(), "\xE9\x8D\xFF\x0A\x00\xFF\xE1\xFF\xD0\xFF\xD5\xFF\xD4"_bytes);
    }

    {
        X86Assembler a(0x123);
        a.push(EAX);
        a.push(ESP);
        a.push(X86Pointer(ESP, 0x10));
        assertEq(a.buffer(), "\x50\x54\xFF\x74\x24\x10"_bytes);
    }

    {
        X86Assembler a(0x123);
        a.mov(EAX, EAX);
        a.mov(ECX, EAX);
        a.mov(ECX, m[EDX + 4]);
        a.mov(ECX, m[EBP + 4]);
        a.mov(m[EBP + 4], ESP);
        a.mov(m[EBP], EAX);
        assertEq(a.buffer(), "\x89\xC0\x89\xC1\x8B\x4A\x04\x8B\x4D\x04\x89\x65\x04\x89\x45\x00"_bytes);
    }

    {
        X86Assembler a(0x123);
        a.movsd(m[ESP], XMM0);
        a.movsd(XMM1, m[ESP + 4]);
        assertEq(a.buffer(), "\xF2\x0F\x11\x04\x24\xF2\x0F\x10\x4C\x24\x04"_bytes);
    }

    {
        X86Assembler a(0x123);
        a.movss(m[ESP], XMM0);
        a.movss(XMM1, m[ESP + 4]);
        assertEq(a.buffer(), "\xF3\x0F\x11\x04\x24\xF3\x0F\x10\x4C\x24\x04"_bytes);
    }
}