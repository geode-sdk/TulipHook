#pragma once

#include <stdint.h>
#include <string>
#include <memory>
#include <vector>
#include "../assembler/BaseAssembler.hpp"

namespace tulip::hook {

    class BaseInstruction {
    public:
        virtual ~BaseInstruction() = default;
    };

	class BaseDisassembler {
	public:
		std::vector<uint8_t> m_input;
        size_t m_currentIndex = 0;
		int64_t m_baseAddress = 0;

		BaseDisassembler(int64_t baseAddress, std::vector<uint8_t> const& input);
		BaseDisassembler(BaseDisassembler const&) = delete;
		BaseDisassembler(BaseDisassembler&&) = delete;
		virtual ~BaseDisassembler();

		virtual bool hasNext() const;
		virtual std::unique_ptr<BaseInstruction> disassembleNext() = 0;

		int32_t extractValue(int startBit, int size, uint32_t instruction, bool signExtend = true);
	};
}