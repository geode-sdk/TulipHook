#include "HooksDef.hpp"
#include <cassert>

#define EXPECT_EQ(a,b) assert(a == b)

CheckSmallStruct128 checkSmallStruct128(CheckSmallStruct128 s) {
	EXPECT_EQ(s.x, 10);
	EXPECT_EQ(s.y, 11);

	return {17, 18};
}

CheckSmallStruct64 checkSmallStruct64(CheckSmallStruct64 s) {
	// add some useless checks here to make the function larger
	EXPECT_EQ(s.a, 8);
	EXPECT_EQ(s.b, 9);

	return {4, 5};
}
