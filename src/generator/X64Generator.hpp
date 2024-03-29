#pragma once

#include "X86Generator.hpp"

#include <Platform.hpp>

namespace tulip::hook {

	class X64HandlerGenerator : public X86HandlerGenerator {
	public:
		using X86HandlerGenerator::X86HandlerGenerator;

		std::vector<uint8_t> handlerBytes(uint64_t address) override;
		std::vector<uint8_t> intervenerBytes(uint64_t address) override;
		std::vector<uint8_t> trampolineBytes(uint64_t address, size_t offset) override;
	};

	class X64WrapperGenerator : public WrapperGenerator {
	public:
		using WrapperGenerator::WrapperGenerator;
	};
}
