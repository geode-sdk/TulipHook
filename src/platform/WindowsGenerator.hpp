#pragma once

#include "../Generator.hpp"

#include <Platform.hpp>

#if defined(TULIP_HOOK_WINDOWS)

namespace tulip::hook {

	class WindowsHandlerGenerator : public HandlerGenerator {
	public:
		using HandlerGenerator::HandlerGenerator;

		Result<> generateHandler() override;
		Result<std::vector<uint8_t>> generateIntervener() override;
		Result<> generateTrampoline(size_t offset) override;
		Result<size_t> relocateOriginal(size_t target) override;

		std::string handlerString() override;
		std::string intervenerString() override;
		std::string trampolineString(size_t offset) override;

		void relocateInstruction(cs_insn* insn, uint64_t& trampolineAddress, uint64_t& originalAddress) override;
	};

	using PlatformHandlerGenerator = WindowsHandlerGenerator;

	class WindowsWrapperGenerator : public WrapperGenerator {
	public:
		using WrapperGenerator::WrapperGenerator;

		Result<void*> generateWrapper() override;

		std::string wrapperString() override;
	};

	using PlatformWrapperGenerator = WindowsWrapperGenerator;

}

#endif