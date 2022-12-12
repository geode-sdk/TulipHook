#pragma once

#include "AbstractFunction.hpp"
#include "AbstractType.hpp"
#include "CallingConvention.hpp"
#include "HandlerData.hpp"
#include "HookData.hpp"
#include "Platform.hpp"
#include "Result.hpp"
#include "platform/PlatformConvention.hpp"

#include <system_error>

namespace tulip::hook {

	TULIP_HOOK_DLL Result<HandlerHandle> createHandler(void* address, HandlerMetadata const& metadata) noexcept;

	TULIP_HOOK_DLL Result<> removeHandler(HandlerHandle const& handler) noexcept;

	TULIP_HOOK_DLL HookHandle createHook(HandlerHandle const& handler, void* address, HookMetadata const& metadata) noexcept;

	TULIP_HOOK_DLL void removeHook(HandlerHandle const& handler, HookHandle const& hook) noexcept;

	TULIP_HOOK_DLL void updateHookMetadata(
		HandlerHandle const& handler, HookHandle const& hook, HookMetadata const& metadata
	) noexcept;
}
