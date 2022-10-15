#pragma once

#include <cstdint>

namespace tulip::hook {
	class HookHandle {
	public:
		void* m_address;
	};

	class HookMetadata {
	public:
		int32_t m_priority;
	};
}
