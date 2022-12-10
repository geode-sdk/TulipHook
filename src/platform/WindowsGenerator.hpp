#pragma once

#include "../Generator.hpp"

#include <Platform.hpp>

#if defined(TULIP_HOOK_WINDOWS)

namespace tulip::hook {

	class WindowsGenerator : public Generator {
	public:
		using Generator::Generator;

		Result<> generateHandler() override;
		Result<std::vector<uint8_t>> generateIntervener() override;
		Result<> generateTrampoline(size_t offset) override;
		Result<size_t> relocateOriginal(size_t target) override;

		std::string handlerString() override;
		std::string intervenerString() override;
		std::string trampolineString(size_t offset) override;
	};

	using PlatformGenerator = WindowsGenerator;

}

#endif