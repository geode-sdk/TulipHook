#pragma once

#include <unordered_map>
#include <memory>
#include <Result.hpp>
#include <HandlerData.hpp>

namespace tulip::hook {
	class Handler;

	class Pool {
	public:
		std::unordered_map<HandlerHandle, std::unique_ptr<Handler>> m_handlers;

		static Pool& get();

		Result<HandlerHandle> createHandler(void* address, HandlerMetadata m_metadata);
		Result<> removeHandler(HandlerHandle const& handler);

		Handler& getHandler(HandlerHandle const& handler);
	};
}
