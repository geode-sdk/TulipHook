#pragma once

#include <HandlerData.hpp>
#include <WrapperData.hpp>
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
        WrapperMetadata const m_wrapperMetadata;

        std::unordered_map<HookHandle, std::unique_ptr<Hook>> m_hooks;
        std::unordered_map<void*, HookHandle> m_handles;

        std::unique_ptr<HandlerContent> m_content;

        void* m_trampoline = nullptr;
        size_t m_trampolineSize = 0;

        void* m_handler = nullptr;
        size_t m_handlerSize = 0;

        void* m_relocated = nullptr;

        std::vector<uint8_t> m_originalBytes;
        std::vector<uint8_t> m_modifiedBytes;

        static std::unique_ptr<Handler> create(void* address, HandlerMetadata const& metadata);
        ~Handler();

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