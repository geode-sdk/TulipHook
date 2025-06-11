#pragma once

#include <HandlerData.hpp>
#include <Geode/Result.hpp>
#include <memory>
#include <unordered_map>

namespace tulip::hook {
	class Handler;

	class Pool {
	public:
		std::unordered_map<HandlerHandle, std::unique_ptr<Handler>> m_handlers;
		std::vector<Handler*> m_handlerList;
		bool m_runtimeInterveningDisabled = false;
		void* m_commonHandlerSpace = nullptr;

		static void getCommonHandlerStatic(void* originalFunction, size_t uniqueIndex, ptrdiff_t trampolineOffset, void* commonHandler, int handlerType);
		void getCommonHandler(void* originalFunction, size_t uniqueIndex, ptrdiff_t trampolineOffset, void* commonHandler, int handlerType);

		static Pool& get();

		geode::Result<HandlerHandle> createHandler(void* address, HandlerMetadata const& metadata);
		geode::Result<> removeHandler(HandlerHandle const& handler);

		Handler& getHandler(HandlerHandle const& handler);

		geode::Result<> disableRuntimeIntervening(void* commonHandlerSpace);
	};
}
