#pragma once

#include <unordered_map>
#include <array>
#include <memory>
#include <vector>
#include <Result.hpp>
#include <HookData.hpp>
#include <HandlerData.hpp>
#include <Platform.hpp>

namespace tulip::hook {
	class Hook;

	struct HandlerContent {
		size_t m_size = 0;
		std::array<void*, 16> m_functions;
	};

	class Handler final {
	private:
		struct NoPublicConstruct {
			explicit NoPublicConstruct() = default;
		};

	public:
		Handler(NoPublicConstruct, void* address, HandlerMetadata metadata);
		
		void* const m_address;
		HandlerMetadata const m_metadata;

		std::unordered_map<HookHandle, std::unique_ptr<Hook>> m_hooks {};

		
		HandlerContent* m_content = nullptr;

		void* m_trampoline = nullptr;
		size_t m_trampolineSize = 0;

		void* m_handler = nullptr;
		size_t m_handlerSize = 0;
		

		std::vector<uint8_t> m_originalBytes;
		std::vector<uint8_t> m_modifiedBytes;

		static Result<std::unique_ptr<Handler>> create(void* address, HandlerMetadata metadata);
		~Handler();

		Result<> init();

		HookHandle createHook(void* address, HookMetadata m_metadata);
		void removeHook(HookHandle const& hook);

		void clearHooks();

		void reorderFunctions();

		static bool TULIP_HOOK_DEFAULT_CONV symbolResolver(char const* symbol, uint64_t* value);

		static TULIP_HOOK_DLL void TULIP_HOOK_DEFAULT_CONV incrementIndex(HandlerContent* content);
		static TULIP_HOOK_DLL void TULIP_HOOK_DEFAULT_CONV decrementIndex();
		static TULIP_HOOK_DLL void* TULIP_HOOK_DEFAULT_CONV getNextFunction(HandlerContent* content);

		Result<> interveneFunction();
		Result<> restoreFunction();

		void generateHandler();
		void generateIntervener();
		void generateTrampoline();
	};
}