#pragma once

#include <map>

#include <HookData.hpp>

namespace tulip::hook {

	class Hook {
	public:
		HookMetadata m_metadata;

		void* m_address;

		Hook(void* address, HookMetadata metadata) : m_address(address), m_metadata(metadata) {}
		~Hook() {}
	};
}