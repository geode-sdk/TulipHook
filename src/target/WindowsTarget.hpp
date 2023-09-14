#pragma once

#include "../generator/X86Generator.hpp"
#include "Target.hpp"

#include <Platform.hpp>

#if defined(TULIP_HOOK_WINDOWS)

namespace tulip::hook {
	class WindowsTarget : public Target {
	public:
		using Target::Target;

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
}

#endif