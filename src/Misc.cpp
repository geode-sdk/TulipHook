#include "Misc.hpp"

using namespace tulip::hook;

Result<void*> Misc::followJumps(void* address) {
	return Err(Error{Error::NotImplemented, "followJumps"});
}
