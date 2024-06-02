#include <Platform.hpp>

#if defined(TULIP_HOOK_WINDOWS) && defined(TULIP_HOOK_X64)

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
}

ThiscallConvention::~ThiscallConvention() {}

void ThiscallConvention::generateDefaultCleanup(BaseAssembler& a_, AbstractFunction const& function) {
    size_t stackParamSize = getStackParamSize(function);
    if (stackParamSize > 0) {
        auto& a = static_cast<X64Assembler&>(a_);
        using enum X64Register;
        auto const paddedSize = (stackParamSize % 16) ? stackParamSize + 8 : stackParamSize;
        a.add(RSP, paddedSize);
    }
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

void ThiscallConvention::generateIntoDefault(BaseAssembler& a_, AbstractFunction const& function) {
    auto& a = static_cast<X64Assembler&>(a_);
    using enum X64Register;
    RegMem64 m;

    if (function.m_return.m_kind == AbstractTypeKind::Other) {
        a.xchg(RCX, RDX);
    }

    size_t stackParamSize = getStackParamSize(function);
    if (stackParamSize > 0) {
        auto const paddedSize = (stackParamSize % 16) ? stackParamSize + 8 : stackParamSize;
        a.sub(RSP, paddedSize);
        int stackOffset = 0;

        for (auto i = 0; i < stackParamSize; i += 8) {
            a.mov(RAX, m[RBP + (32 + i)]);
            a.mov(m[RSP + i], RAX);
        }
    }
}

void ThiscallConvention::generateIntoOriginal(BaseAssembler& a_, AbstractFunction const& function) {
    auto& a = static_cast<X64Assembler&>(a_);
    using enum X64Register;
    RegMem64 m;

    if (function.m_return.m_kind == AbstractTypeKind::Other) {
        a.xchg(RCX, RDX);
    }
}

void ThiscallConvention::generateOriginalCleanup(BaseAssembler& a, AbstractFunction const& function) {
}

bool ThiscallConvention::needsWrapper(AbstractFunction const& function) const {
	return function.m_return.m_kind == AbstractTypeKind::Other;
}

std::shared_ptr<ThiscallConvention> ThiscallConvention::create() {
	return std::make_shared<ThiscallConvention>();
}

#endif