#pragma once

#include <TulipResult.hpp>

namespace tulip::hook {

	class Misc {
	public:
		static Result<void*> followJumps(void* address);
	};
}