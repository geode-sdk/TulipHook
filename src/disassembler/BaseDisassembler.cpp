#include "BaseDisassembler.hpp"

using namespace tulip::hook;

BaseDisassembler::BaseDisassembler(int64_t baseAddress, std::vector<uint8_t> const& input) :
    m_baseAddress(baseAddress), m_input(input) {}

BaseDisassembler::~BaseDisassembler() = default;

bool BaseDisassembler::hasNext() const {
    return m_currentIndex < m_input.size();
}

int32_t BaseDisassembler::extractValue(int startBit, int size, uint32_t instruction, bool signExtend) {
    auto const defaultMask = (1 << size) - 1;
    auto const offsetValue = (instruction >> startBit);
    auto const extractedValue = offsetValue & defaultMask;
    if (signExtend) {
        auto const signMask = 1 << (size - 1);
        if (extractedValue & signMask) {
            auto const negativeMask = ~defaultMask;
            return extractedValue | negativeMask;
        }
    }
    return extractedValue;
}