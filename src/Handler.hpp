#pragma once

#include <map>
#include <array>
#include <memory>
#include <vector>

#include <HookData.hpp>
#include <HandlerData.hpp>
#include <Platform.hpp>

namespace tulip::hook {
	class Hook;

	struct HandlerContent {
		size_t m_size = 0;
		std::array<void*, 16> m_functions;
	};

	class Handler {
	public:
		void* m_address;
		HandlerMetadata m_metadata;

		std::map<HookHandle, std::unique_ptr<Hook>> m_hooks;

		
		HandlerContent* m_content = nullptr;

		void* m_trampoline = nullptr;
		size_t m_trampolineSize = 0;

		void* m_handler = nullptr;
		size_t m_handlerSize = 0;
		

		std::vector<uint8_t> m_originalBytes;
		std::vector<uint8_t> m_modifiedBytes;

		Handler(void* address, HandlerMetadata metadata);
		~Handler();

		void init();

		HookHandle createHook(void* address, HookMetadata m_metadata);
		void removeHook(HookHandle const& hook);

		void clearHooks();

		void reorderFunctions();

		std::string handlerString();
		std::string intervenerString();
		std::string trampolineString(size_t offset);
		static bool symbolResolver(char const* symbol, uint64_t* value);

		static TULIP_HOOK_DLL TULIP_HOOK_DEFAULT_CONV void incrementIndex(HandlerContent* content);
		static TULIP_HOOK_DLL TULIP_HOOK_DEFAULT_CONV void decrementIndex();
		static TULIP_HOOK_DLL TULIP_HOOK_DEFAULT_CONV void* getNextFunction(HandlerContent* content);

		void interveneFunction();
		void restoreFunction();

		void generateHandler();
		void generateIntervener();
		void generateTrampoline();
	};
}