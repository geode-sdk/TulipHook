#pragma once

#include <system_error>

#include "Platform.hpp"

#include "AbstractFunction.hpp"
#include "AbstractType.hpp"
#include "CallingConvention.hpp"
#include "HandlerData.hpp"
#include "HookData.hpp"

#include "platform/WindowsCallingConvention.hpp"

namespace tulip::hook {

	TULIP_HOOK_DLL HandlerHandle createHandler(void* address, HandlerMetadata metadata);

	TULIP_HOOK_DLL void removeHandler(HandlerHandle const& handler);

	TULIP_HOOK_DLL HookHandle createHook(HandlerHandle const& handler, void* address, HookMetadata metadata) noexcept;

	TULIP_HOOK_DLL void removeHook(HandlerHandle const& handler, HookHandle const& hook) noexcept;

}