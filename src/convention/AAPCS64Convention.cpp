#include <Platform.hpp>

#include <AbstractFunction.hpp>
#include <platform/AAPCS64Convention.hpp>
#include "../assembler/ArmV8Assembler.hpp"

using namespace tulip::hook;

namespace {
    size_t getStackParamSize(AbstractFunction const& function) {
        size_t stackParamSize = 0;
        int vectorCount = 0;
        int gprCount = 0;
        if (function.m_return.m_kind == AbstractTypeKind::Other && function.m_return.m_size > 16) {
            gprCount += 1;
        }
        for (auto& param : function.m_parameters) {
            if (param.m_kind == AbstractTypeKind::FloatingPoint) {
                if (vectorCount < 8) {
                    vectorCount++;
                } else {
                    stackParamSize += 8;
                }
            } else if (param.m_kind == AbstractTypeKind::Primitive && param.m_size == 16) {
                if (gprCount < 8) {
                    gprCount++;
                } else {
                    stackParamSize += 8;
                }
                if (gprCount < 8) {
                    gprCount++;
                } else {
                    stackParamSize += 8;
                }
            } else {
                if (gprCount < 8) {
                    gprCount++;
                } else {
                    stackParamSize += 8;
                }
            }
        }
        return stackParamSize;
    }
}

AAPCS64Convention::~AAPCS64Convention() {}

void AAPCS64Convention::generateDefaultCleanup(BaseAssembler& a_, AbstractFunction const& function) {
    size_t stackParamSize = getStackParamSize(function);
    if (stackParamSize > 0) {
        auto& a = static_cast<ArmV8Assembler&>(a_);
        using enum ArmV8Register;
        auto const paddedSize = stackParamSize + (16 - (stackParamSize % 16)) % 16; // pad to 16 bytes
    }
}

// used to move the stack values to the correct places

void AAPCS64Convention::generateIntoDefault(BaseAssembler& a_, AbstractFunction const& function) {
    size_t stackParamSize = getStackParamSize(function);
    if (stackParamSize > 0) {
        auto& a = static_cast<ArmV8Assembler&>(a_);
        using enum ArmV8Register;
        
        int stackOffset = 0;
        auto const paddedSize = stackParamSize + (16 - (stackParamSize % 16)) % 16; // pad to 16 bytes
        for (auto i = 0; i < stackParamSize; i += 16) {
            // X29 is the frame pointer (old sp-10), X16 and X17 are temporary registers
            a.ldp(X16, X17, X29, i + 16, ArmV8IndexKind::SignedOffset);
            a.stp(X16, X17, SP, i, ArmV8IndexKind::SignedOffset);
        }
    }
}

void AAPCS64Convention::generateIntoOriginal(BaseAssembler& a_, AbstractFunction const& function) {
}

void AAPCS64Convention::generateOriginalCleanup(BaseAssembler& a_, AbstractFunction const& function) {
}

bool AAPCS64Convention::needsWrapper(AbstractFunction const& function) const {
	return false;
}

std::shared_ptr<AAPCS64Convention> AAPCS64Convention::create() {
	return std::make_shared<AAPCS64Convention>();
}
