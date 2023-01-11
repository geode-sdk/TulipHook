#pragma once

#include <TulipResult.hpp>
#include <WrapperData.hpp>
#include <memory>
#include <unordered_map>

namespace tulip::hook {
	class Handler;

	class Wrapper {
	public:
		std::unordered_map<void*, void*> m_wrappers;

		static Wrapper& get();

		Result<void*> createWrapper(void* address, WrapperMetadata const& metadata);
	};
}
