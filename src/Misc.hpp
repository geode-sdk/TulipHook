#pragma once

#include <Result.hpp>

namespace tulip::hook {

	class Misc {
	public:
		static Result<void*> followJumps(void* address);
	};
}