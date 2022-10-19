#pragma once

#include <cstdint>

namespace tulip::hook {
	using HookHandle = size_t;

	class HookMetadata {
	public:
		int32_t m_priority = 0;
	};
}
