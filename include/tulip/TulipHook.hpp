#pragma once

#include "CallingConvention.hpp"
#include "Error.hpp"
#include "HandlerData.hpp"
#include "HookData.hpp"
#include "Platform.hpp"
#include <optional>
#include "WrapperData.hpp"
#include "platform/PlatformConvention.hpp"

#include <functional>

namespace tulip::hook {
	TULIP_HOOK_DLL Result<HandlerHandle> createHandler(void* address, HandlerMetadata const& metadata) noexcept;

	TULIP_HOOK_DLL Result<void> removeHandler(HandlerHandle const& handler) noexcept;

	TULIP_HOOK_DLL HookHandle createHook(HandlerHandle const& handler, void* address, HookMetadata const& metadata) noexcept;

	TULIP_HOOK_DLL void removeHook(HandlerHandle const& handler, HookHandle const& hook) noexcept;

	TULIP_HOOK_DLL void updateHookMetadata(
		HandlerHandle const& handler, HookHandle const& hook, HookMetadata const& metadata
	) noexcept;

	TULIP_HOOK_DLL Result<void> writeMemory(void* destination, void const* source, size_t size) noexcept;

	TULIP_HOOK_DLL Result<void*> followJumps(void* address) noexcept;

	// wraps a cdecl function into given convention
	TULIP_HOOK_DLL Result<void*> createWrapper(void* address, WrapperMetadata const& metadata) noexcept;

	// wraps a function in given convention into cdecl
	TULIP_HOOK_DLL Result<void*> createReverseWrapper(void* address, WrapperMetadata const& metadata) noexcept;

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

	TULIP_HOOK_DLL Result<void> disableRuntimeIntervening(void* commonHandlerSpace) noexcept;

	struct RelocaledBytesReturn {
		std::vector<uint8_t> bytes;
		size_t offset;
		std::string error;
	};
	TULIP_HOOK_DLL RelocaledBytesReturn getRelocatedBytes(int64_t original, int64_t relocated, std::vector<uint8_t> const& originalBuffer);
	TULIP_HOOK_DLL std::vector<uint8_t> getCommonHandlerBytes(int64_t handler, ptrdiff_t spaceOffset);
	TULIP_HOOK_DLL std::vector<uint8_t> getCommonIntervenerBytes(int64_t original, int64_t handler, size_t unique, ptrdiff_t relocOffset);

	TULIP_HOOK_DLL void setLogCallback(std::function<void(std::string_view)> callback) noexcept;

	struct FunctionInformationReturn {
		void* start;
		void* end;
		enum class Type {
			Handler = 0, // the main handler
			Relocated = 1, // relocated function
			Trampoline = 2, // relocated function wrapped in a trampoline
			Intervener = 32, // the function that jumps to handler
			RuntimeInfo = 33, // runtime information
		};
		Type type;
	};

	TULIP_HOOK_DLL std::optional<FunctionInformationReturn> getFunctionInformation(void* address) noexcept;

}
