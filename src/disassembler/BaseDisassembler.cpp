#include "BaseDisassembler.hpp"

using namespace tulip::hook;

BaseDisassembler::BaseDisassembler(int64_t baseAddress, std::vector<uint8_t> const& input) :
    m_baseAddress(baseAddress), m_input(input) {}

BaseDisassembler::~BaseDisassembler() = default;

bool BaseDisassembler::hasNext() const {
    return m_currentIndex < m_input.size();
}