#pragma once

#include <system_error>

#include "Platform.hpp"

#include "AbstractFunction.hpp"
#include "AbstractType.hpp"
#include "CallingConvention.hpp"
#include "Handler.hpp"
#include "Hook.hpp"

namespace tulip::hook {

	TULIP_HOOK_DLL HandlerHandle createHandler(void* address, HandlerMetadata&& metadata, std::error_code& error) noexcept;
	TULIP_HOOK_DLL HandlerHandle createHandler(void* address, HandlerMetadata&& metadata);

	TULIP_HOOK_DLL void removeHandler(HandlerHandle const& handler, std::error_code& error) noexcept;
	TULIP_HOOK_DLL void removeHandler(HandlerHandle const& handler);

	TULIP_HOOK_DLL HookHandle createHook(HandlerHandle const& handler, void* address, HookMetadata&& metadata, std::error_code& error) noexcept;
	TULIP_HOOK_DLL HookHandle createHook(HandlerHandle const& handler, void* address, HookMetadata&& metadata) noexcept;

	TULIP_HOOK_DLL void removeHook(HookHandle const& hook, std::error_code& error) noexcept;
	TULIP_HOOK_DLL void removeHook(HookHandle const& hook) noexcept;

}