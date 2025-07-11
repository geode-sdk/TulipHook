#include <Platform.hpp>

#include <AbstractFunction.hpp>
#include <platform/AAPCSConvention.hpp>
#include "../assembler/ThumbV7Assembler.hpp"

using namespace tulip::hook;

namespace {
    size_t getStackParamSize(AbstractFunction const& function) {
        // assumes soft-float ABI
        size_t stackParamSize = 0;
        int gprCount = 0;
        if (function.m_return.m_kind == AbstractTypeKind::Other && function.m_return.m_size > 8) {
            gprCount += 1;
        }
        for (auto& param : function.m_parameters) {
            if (param.m_kind == AbstractTypeKind::Primitive && param.m_size == 8) {
                if (gprCount < 4) {
                    gprCount++;
                } else {
                    stackParamSize += 4;
                }
                if (gprCount < 4) {
                    gprCount++;
                } else {
                    stackParamSize += 4;
                }
            } else if (param.m_kind == AbstractTypeKind::Other) {
                // floor + add one slot to align to an 8 byte boundary
                auto slotsNeeded = (param.m_size + 3) / 4 + 1;

                auto remainingRegs = gprCount > 4 ? 0 : 4 - gprCount;
                if (slotsNeeded < remainingRegs) {
                    gprCount += slotsNeeded;
                } else {
                    gprCount += remainingRegs;
                    slotsNeeded -= remainingRegs;
                }

                stackParamSize += slotsNeeded * 4;
            } else {
                if (gprCount < 4) {
                    gprCount++;
                } else {
                    stackParamSize += 4;
                }
            }
        }
        return stackParamSize;
    }
}

AAPCSConvention::~AAPCSConvention() {}

void AAPCSConvention::generateDefaultCleanup(BaseAssembler& a_, AbstractFunction const& function) {
    size_t stackParamSize = getStackParamSize(function);
    if (stackParamSize > 0) {
        auto& a = static_cast<ThumbV7Assembler&>(a_);
        using enum ArmV7Register;
        auto const paddedSize = stackParamSize + (16 - (stackParamSize % 16)) % 16; // pad to 16 bytes
        // a.add(SP, paddedSize);
    }
}

// used to move the stack values to the correct places

void AAPCSConvention::generateIntoDefault(BaseAssembler& a_, AbstractFunction const& function) {
    size_t stackParamSize = getStackParamSize(function);
    if (stackParamSize > 0) {
        auto& a = static_cast<ThumbV7Assembler&>(a_);
        using enum ArmV7Register;
        
        // a.sub(SP, paddedSize);
        int stackOffset = 0;
        auto const paddedSize = stackParamSize + (16 - (stackParamSize % 16)) % 16; // pad to 16 bytes
        for (auto i = 0; i < stackParamSize; i += 4) {
            // R11 is the frame pointer, R5 is a saved temporary register
            a.ldrw(R5, R11, 16 + i);
            a.str(R5, SP, i);
        }
    }
}

void AAPCSConvention::generateIntoOriginal(BaseAssembler& a_, AbstractFunction const& function) {
}

void AAPCSConvention::generateOriginalCleanup(BaseAssembler& a_, AbstractFunction const& function) {
}

bool AAPCSConvention::needsWrapper(AbstractFunction const& function) const {
	return false;
}

std::shared_ptr<AAPCSConvention> AAPCSConvention::create() {
	return std::make_shared<AAPCSConvention>();
}
