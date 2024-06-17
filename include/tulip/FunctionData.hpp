#pragma once

#include <cstdint>

namespace tulip::hook {
	struct FunctionData {
		void* m_address;
        size_t m_size;
	};
}
