#include <cstdint>

struct CheckParamsStruct {
	int a;
	int b;
	int c;
	int d;
	double e;
	int f;
	int g;
	float h;
	int i;
	int j;
	int k;
	int l;
	std::int64_t m;
	int n;
	int o;
	int p;
	int q;
	int r;
	int s;
};

int checkParams(int a, int b, int c, int d, int e, int f, int g, float h, int i, int j, int k, int l, int m, int n, int o, int p, int q, int r, int s);

int checkStructParams(int a, CheckParamsStruct s);

// should be passed through X0-X1 on ARM64
struct CheckSmallStruct128 {
	std::uint64_t x;
	std::uint64_t y;
};

CheckSmallStruct128 checkSmallStruct128(CheckSmallStruct128 s);

// should be passed either in one register (ARM64) or two (ARMv7)
struct CheckSmallStruct64 {
	std::uint32_t a;
	std::uint32_t b;
};

CheckSmallStruct64 checkSmallStruct64(CheckSmallStruct64 s);
