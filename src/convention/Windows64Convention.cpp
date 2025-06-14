#include <Platform.hpp>

#include <AbstractFunction.hpp>
#include <platform/Windows64Convention.hpp>
#include "../assembler/X64Assembler.hpp"

using namespace tulip::hook;

namespace {
    size_t getStackParamSize(AbstractFunction const& function) {
        size_t stackParamSize = 0;
        int regCount = 0;
        if (function.m_return.m_kind == AbstractTypeKind::Other) {
            regCount += 1;
        }
        for (auto& param : function.m_parameters) {
            if (regCount < 4) {
                regCount++;
            } else {
                stackParamSize += 8;
            }
        }
        return stackParamSize;
    }
    size_t getPaddedStackParamSize(AbstractFunction const& function) {
        auto stackParamSize = getStackParamSize(function);
        return (stackParamSize % 16) ? stackParamSize + 8 : stackParamSize;
    }
}

Windows64Convention::~Windows64Convention() {}

void Windows64Convention::generateDefaultCleanup(BaseAssembler& a_, AbstractFunction const& function) {
    auto& a = static_cast<X64Assembler&>(a_);
    using enum X64Register;

    // size_t paddedSize = getPaddedStackParamSize(function);
    // a.add(RSP, paddedSize + 0x20);
}

void Windows64Convention::generateIntoDefault(BaseAssembler& a_, AbstractFunction const& function) {
    auto& a = static_cast<X64Assembler&>(a_);
    using enum X64Register;
    RegMem64 m;

    size_t stackParamSize = getStackParamSize(function);
    auto const paddedSize = (stackParamSize % 16) ? stackParamSize + 8 : stackParamSize;
    // + 0x20 for the shadow space before the first arg
    // a.sub(RSP, paddedSize + 0x20);
    // a.label("convention-alloc-small");
    if (stackParamSize > 0) {
        // theres stack args, so we need to copy them over

        // RBP points to this (each cell is 8 bytes):
        // [orig rbp] [return ptr] [] [] [] [] [1st stack arg] ...
        // rbp + 0    rbp + 8                  rbp + 0x30 ...
        // new stack will look like
        // [] [] [] [] [1st stack arg] ...
        //             rsp + 0x20 ...

        for (auto i = 0; i < stackParamSize; i += 8) {
            a.mov(RAX, m[RBP + (0x30 + i)]);
            a.mov(m[RSP + (0x20 + i)], RAX);
        }
    }
}

std::shared_ptr<Windows64Convention> Windows64Convention::create() {
	return std::make_shared<Windows64Convention>();
}

// Member functions deal with struct return differently, since in the windows x64 convention
// a struct return is as a hidden first parameter, member functions end up considering the first parameter
// the one after the `this`, whereas static functions do not.
//
// So where a static function would behave like this:
// SomeStruct* func(SomeStruct* ret_ptr, Class* self, int a, int b);
// a member function would behave like this:
// SomeStruct* Class::method(Class* this, SomeStruct* ret_ptr, int a, int b);
// so to undo this we just swap the first two parameters (RCX and RDX).

Thiscall64Convention::~Thiscall64Convention() {}

void Thiscall64Convention::generateIntoDefault(BaseAssembler& a_, AbstractFunction const& function) {
    auto& a = static_cast<X64Assembler&>(a_);
    using enum X64Register;
    RegMem64 m;

    if (function.m_return.m_kind == AbstractTypeKind::Other) {
        a.xchg(RCX, RDX);
    }

    Windows64Convention::generateIntoDefault(a, function);
}

void Thiscall64Convention::generateIntoOriginal(BaseAssembler& a_, AbstractFunction const& function) {
    auto& a = static_cast<X64Assembler&>(a_);
    using enum X64Register;
    RegMem64 m;

    if (function.m_return.m_kind == AbstractTypeKind::Other) {
        a.xchg(RCX, RDX);
    }

    // the wrapper requires the struct forwarding as well
    Windows64Convention::generateIntoDefault(a, function);
}

void Thiscall64Convention::generateOriginalCleanup(BaseAssembler& a_, AbstractFunction const& function) {
    // the wrapper requires the struct forwarding as well
    Windows64Convention::generateDefaultCleanup(a_, function);
}

bool Thiscall64Convention::needsWrapper(AbstractFunction const& function) const {
	return function.m_return.m_kind == AbstractTypeKind::Other;
}

std::shared_ptr<Thiscall64Convention> Thiscall64Convention::create() {
	return std::make_shared<Thiscall64Convention>();
}