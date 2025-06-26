#pragma once

#include <FunctionData.hpp>
#include <Geode/Result.hpp>
#include <WrapperData.hpp>
#include <memory>
#include <unordered_map>

namespace tulip::hook {
	class Handler;

	struct WrapperData {
		void* m_address = nullptr;
		void* m_runtimeInfo = nullptr;
	};

	class Wrapper {
	public:
		std::unordered_map<void*, WrapperData> m_wrappers;
		std::unordered_map<void*, WrapperData> m_reverseWrappers;

		static Wrapper& get();

		geode::Result<void*> createWrapper(void* address, WrapperMetadata const& metadata);
		geode::Result<void*> createReverseWrapper(void* address, WrapperMetadata const& metadata);
	};
}
