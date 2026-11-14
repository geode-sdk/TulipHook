#pragma once

#include <Platform.hpp>

#if defined(TULIP_HOOK_IOS) && defined(TULIP_HOOK_ARMV8)

#include "../generator/ArmV8Generator.hpp"
#include "DarwinTarget.hpp"

namespace tulip::hook {
	class iOSTarget : public DarwinTarget {
	public:
		using DarwinTarget::DarwinTarget;

		Result<> allocatePage() override;
		Result<> rawWriteMemory(void* destination, void const* source, size_t size) override;
		Result<> protectMemory(void* address, size_t size, uint32_t protection) override;

		Result<csh> openCapstone() override;

		std::unique_ptr<BaseGenerator> getGenerator() override;

		uint32_t getWritableProtection() override;

		std::shared_ptr<CallingConvention> createConvention(TulipConvention convention) noexcept override;

		bool m_useTxmJIT;
	};
}

#endif
