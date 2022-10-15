#pragma once

#include <map>
#include <memory>

#include <HandlerData.hpp>

namespace tulip::hook {
	class Handler;

	class Pool {
	public:
		std::map<HandlerHandle, std::unique_ptr<Handler>> m_handlers;

		static Pool& get();

		HandlerHandle createHandler(void* address, HandlerMetadata m_metadata);
		void removeHandler(HandlerHandle const& handler);

		Handler& getHandler(HandlerHandle const& handler);
	};
}