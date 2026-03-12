#include "HooksDef.hpp"
#include <cassert>

#define EXPECT_EQ(a,b) assert(a == b)

int checkParams(int a, int b, int c, int d, int e, int f, int g, float h, int i, int j, int k, int l, int m, int n, int o, int p, int q, int r, int s) {
	EXPECT_EQ(a, 1);
	EXPECT_EQ(b, 2);
	EXPECT_EQ(c, 3);
	EXPECT_EQ(d, 4);
	EXPECT_EQ(e, 5);
	EXPECT_EQ(f, 6);
	EXPECT_EQ(g, 7);
	EXPECT_EQ(h, 8.0f);
	EXPECT_EQ(i, 9);
	EXPECT_EQ(j, 10);
	EXPECT_EQ(k, 11);
	EXPECT_EQ(l, 12);
	EXPECT_EQ(m, 13);
	EXPECT_EQ(n, 14);
	EXPECT_EQ(o, 15);
	EXPECT_EQ(p, 16);
	EXPECT_EQ(q, 17);
	EXPECT_EQ(r, 18);
	EXPECT_EQ(s, 19);

	return 11;
}

int checkStructParams(int a, CheckParamsStruct s) {
	EXPECT_EQ(a, -1);
	EXPECT_EQ(s.a, 1);
	EXPECT_EQ(s.b, 2);
	EXPECT_EQ(s.c, 3);
	EXPECT_EQ(s.d, 4);
	EXPECT_EQ(s.e, 123456789.1234);
	EXPECT_EQ(s.f, 6);
	EXPECT_EQ(s.g, 7);
	EXPECT_EQ(s.h, 8.0f);
	EXPECT_EQ(s.i, 9);
	EXPECT_EQ(s.j, 10);
	EXPECT_EQ(s.k, 11);
	EXPECT_EQ(s.l, 12);
	EXPECT_EQ(s.m, 123456789123456789ll);
	EXPECT_EQ(s.n, 14);
	EXPECT_EQ(s.o, 15);
	EXPECT_EQ(s.p, 16);
	EXPECT_EQ(s.q, 17);
	EXPECT_EQ(s.r, 18);
	EXPECT_EQ(s.s, 19);

	return 4;
}

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
