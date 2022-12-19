#pragma once

#include <HandlerData.hpp>
#include <TulipResult.hpp>
#include <memory>
#include <unordered_map>

namespace tulip::hook {
	class Handler;

	class Pool {
	public:
		std::unordered_map<HandlerHandle, std::unique_ptr<Handler>> m_handlers;

		static Pool& get();

		Result<HandlerHandle> createHandler(void* address, HandlerMetadata const& metadata);
		Result<> removeHandler(HandlerHandle const& handler);

		Handler& getHandler(HandlerHandle const& handler);
	};
}
