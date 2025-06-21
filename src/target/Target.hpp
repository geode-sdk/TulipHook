#pragma once

#include <HandlerData.hpp>
#include <Geode/Result.hpp>
#include <WrapperData.hpp>
#include <FunctionData.hpp>
#include <memory>
#include <functional>
#include <TulipHook.hpp>

#include <Platform.hpp>
#if defined(TULIP_HOOK_X86) || defined(TULIP_HOOK_X64)
#include <capstone/capstone.h>
#else
typedef size_t csh;
#endif

namespace tulip::hook {
    class BaseGenerator;
    class Target {
    protected:
        csh m_capstone = 0;

        void* m_allocatedPage = nullptr;
        size_t m_currentOffset = 0;
        size_t m_remainingOffset = 0;
        std::function<void(std::string_view)> m_logCallback;

    public:
        static Target& get();

        virtual ~Target() = default;

        geode::Result<void*> allocateArea(size_t size);
        geode::Result<void*> peekArea();

        virtual geode::Result<> writeMemory(void* destination, void const* source, size_t size);

        virtual geode::Result<csh> openCapstone() = 0;
        void closeCapstone();
        csh getCapstone();

        virtual geode::Result<> allocatePage() = 0;
        virtual geode::Result<uint32_t> getProtection(void* address) = 0;
        virtual geode::Result<> protectMemory(void* address, size_t size, uint32_t protection) = 0;
        virtual geode::Result<> rawWriteMemory(void* destination, void const* source, size_t size) = 0;
        virtual uint32_t getWritableProtection() = 0;

        virtual std::unique_ptr<BaseGenerator> getGenerator() = 0;

        // These just exist because of arm7! fun!
        virtual int64_t getRealPtr(void* ptr);
        virtual int64_t getRealPtrAs(void* ptr, void* lookup);

        void registerLogCallback(std::function<void(std::string_view)> callback);
        void log(std::function<std::string()> callback);

        virtual std::shared_ptr<CallingConvention> createConvention(TulipConvention convention) noexcept = 0;
    };
};
