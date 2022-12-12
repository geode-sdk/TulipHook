#include "Misc.hpp"

#include "platform/PlatformGenerator.hpp"
#include "platform/PlatformTarget.hpp"

using namespace tulip::hook;

Result<void*> Misc::followJumps(void* address) {
	return Err("Implement followJumps in platform");
}