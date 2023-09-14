#pragma once

#include "../generator/X64Generator.hpp"
#include "Target.hpp"

#include <Platform.hpp>

#if defined(TULIP_HOOK_MACOS)

namespace tulip::hook {
	class MacosTarget : public Target {
	public:
		using Target::Target;

		static MacosTarget& get();

		Result<csh> openCapstone() override;

		Result<> allocatePage() override;
		Result<uint32_t> getProtection(void* address) override;
		Result<> protectMemory(void* address, size_t size, uint32_t protection) override;
		Result<> rawWriteMemory(void* destination, void const* source, size_t size) override;
		uint32_t getMaxProtection() override;

		std::unique_ptr<HandlerGenerator> getHandlerGenerator(
			void* address, void* trampoline, void* handler, void* content, void* wrapped, HandlerMetadata const& metadata
		) override;
		std::unique_ptr<WrapperGenerator> getWrapperGenerator(void* address, WrapperMetadata const& metadata) override;
	};

	using PlatformTarget = MacosTarget;

}

#endif