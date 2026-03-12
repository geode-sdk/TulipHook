#include <cstdint>

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
