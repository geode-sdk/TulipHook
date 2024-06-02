#include <Platform.hpp>

#if defined(TULIP_HOOK_MACOS) && defined(TULIP_HOOK_X64)

#include <AbstractFunction.hpp>
#include <platform/MacosIntelConvention.hpp>
#include "../assembler/X64Assembler.hpp"

using namespace tulip::hook;

namespace {
    size_t getStackParamSize(AbstractFunction const& function) {
        size_t stackParamSize = 0;
        int xmmCount = 0;
        int gprCount = 0;
        if (function.m_return.m_kind == AbstractTypeKind::Other && function.m_return.m_size > 16) {
            gprCount += 1;
        }
        for (auto& param : function.m_parameters) {
            if (param.m_kind == AbstractTypeKind::FloatingPoint) {
                if (xmmCount < 8) {
                    xmmCount++;
                } else {
                    stackParamSize += 8;
                }
            } else {
                if (gprCount < 6) {
                    gprCount++;
                } else {
                    stackParamSize += 8;
                }
            }
        }
        return stackParamSize;
    }
}

SystemVConvention::~SystemVConvention() {}

void SystemVConvention::generateDefaultCleanup(BaseAssembler& a_, AbstractFunction const& function) {
    size_t stackParamSize = getStackParamSize(function);
    if (stackParamSize > 0) {
        auto& a = static_cast<X64Assembler&>(a_);
        using enum X64Register;
        auto const paddedSize = (stackParamSize % 16) ? stackParamSize + 8 : stackParamSize;
        a.add(RSP, paddedSize);
    }
}

// used to move the stack values to the correct places

void SystemVConvention::generateIntoDefault(BaseAssembler& a_, AbstractFunction const& function) {
    size_t stackParamSize = getStackParamSize(function);
    if (stackParamSize > 0) {
        auto& a = static_cast<X64Assembler&>(a_);
        using enum X64Register;
        RegMem64 m;
        auto const paddedSize = (stackParamSize % 16) ? stackParamSize + 8 : stackParamSize;
        a.sub(RSP, paddedSize);
        int stackOffset = 0;

        for (auto i = 0; i < stackParamSize; i += 8) {
            a.mov(RAX, m[RBP + (16 + i)]);
            a.mov(m[RSP + i], RAX);
        }
    }
}

void SystemVConvention::generateIntoOriginal(BaseAssembler& a_, AbstractFunction const& function) {
}

void SystemVConvention::generateOriginalCleanup(BaseAssembler& a_, AbstractFunction const& function) {
}

bool SystemVConvention::needsWrapper(AbstractFunction const& function) const {
	return false;
}

std::shared_ptr<SystemVConvention> SystemVConvention::create() {
	return std::make_shared<SystemVConvention>();
}

#endif