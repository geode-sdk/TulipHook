#pragma once

#include <Platform.hpp>
#include "../Generator.hpp"

#if defined(TULIP_HOOK_MACOS)

namespace tulip::hook {

	class MacosGenerator : public Generator {
	public:
		using Generator::Generator;

		void generateHandler() override;
		std::vector<uint8_t> generateIntervener() override;
		void generateTrampoline(size_t offset) override;
		size_t relocateOriginal(size_t target) override;

		std::string handlerString() override;
		std::string intervenerString() override;
		std::string trampolineString(size_t offset) override;
	};

	using PlatformGenerator = MacosGenerator;

}

#endif