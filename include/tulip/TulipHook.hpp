#pragma once

#include "AbstractFunction.hpp"
#include "AbstractType.hpp"
#include "CallingConvention.hpp"
#include "FunctionData.hpp"
#include "HandlerData.hpp"
#include "HookData.hpp"
#include "Platform.hpp"
#include <Geode/Result.hpp>
#include "WrapperData.hpp"
#include "platform/PlatformConvention.hpp"

#include <system_error>

namespace tulip::hook {
	TULIP_HOOK_DLL geode::Result<HandlerHandle> createHandler(void* address, HandlerMetadata const& metadata) noexcept;

	TULIP_HOOK_DLL geode::Result<void, std::string> removeHandler(HandlerHandle const& handler) noexcept;

	TULIP_HOOK_DLL HookHandle createHook(HandlerHandle const& handler, void* address, HookMetadata const& metadata) noexcept;

	TULIP_HOOK_DLL void removeHook(HandlerHandle const& handler, HookHandle const& hook) noexcept;

	TULIP_HOOK_DLL void updateHookMetadata(
		HandlerHandle const& handler, HookHandle const& hook, HookMetadata const& metadata
	) noexcept;

	TULIP_HOOK_DLL geode::Result<void, std::string> writeMemory(void* destination, void const* source, size_t size) noexcept;

	TULIP_HOOK_DLL geode::Result<void*, std::string> followJumps(void* address) noexcept;

	// wraps a cdecl function into given convention
	TULIP_HOOK_DLL geode::Result<void*, std::string> createWrapper(void* address, WrapperMetadata const& metadata) noexcept;

	// wraps a function in given convention into cdecl
	TULIP_HOOK_DLL geode::Result<void*, std::string> createReverseWrapper(void* address, WrapperMetadata const& metadata) noexcept;

	enum class TulipConvention {
		Default,
		Cdecl,
		Thiscall,
		Fastcall,
		Optcall,
		Membercall,
		Stdcall,
	};

	TULIP_HOOK_DLL std::shared_ptr<CallingConvention> createConvention(TulipConvention convention) noexcept;
}
