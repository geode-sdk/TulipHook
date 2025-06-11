#pragma once

#include <HandlerData.hpp>
#include <HookData.hpp>
#include <Platform.hpp>
#include <Geode/Result.hpp>
#include <array>
#include <memory>
#include <unordered_map>
#include <vector>

namespace tulip::hook {
	class Hook;

	struct HandlerContent {
		std::vector<void*> m_functions;
	};

	class Handler final {
	public:
		Handler(void* address, HandlerMetadata const& metadata);

		void* const m_address;
		HandlerMetadata const m_metadata;

		std::unordered_map<HookHandle, std::unique_ptr<Hook>> m_hooks;
		std::unordered_map<void*, HookHandle> m_handles;

		HandlerContent* m_content = nullptr;

		void* m_trampoline = nullptr;
		size_t m_trampolineSize = 0;

		void* m_handler = nullptr;
		size_t m_handlerSize = 0;

		std::vector<uint8_t> m_originalBytes;
		std::vector<uint8_t> m_modifiedBytes;

		static geode::Result<std::unique_ptr<Handler>> create(void* address, HandlerMetadata const& metadata);
		static geode::Result<std::unique_ptr<Handler>> create(void* address, HandlerMetadata2 const& metadata);
		~Handler();

		geode::Result<> init(std::vector<uint8_t> const& originalBytes);
		geode::Result<> init();

		HookHandle createHook(void* address, HookMetadata m_metadata);
		void removeHook(HookHandle const& hook);

		void clearHooks();

		void addOriginal();

		void reorderFunctions();

		void updateHookMetadata(HookHandle const& hook, HookMetadata const& metadata);

		static void incrementIndex(HandlerContent* content);
		static void decrementIndex();
		static void* getNextFunction(HandlerContent* content);

		static void* popData();
		static void pushData(void* data);

		geode::Result<> interveneFunction();
		geode::Result<> restoreFunction();
	};
}