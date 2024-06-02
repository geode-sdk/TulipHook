#include <gtest/gtest.h>

#include <array>
#include <tulip/TulipHook.hpp>

using namespace tulip::hook;

std::string prettify(std::string str) {
	size_t f;
	while ((f = str.find("; ")) != std::string::npos) {
		str = str.replace(str.begin() + (ptrdiff_t)f, str.begin() + (ptrdiff_t)f + 2, "\n", 1);
	}
	return str;
}

struct Big {
	int x;
	int y;
	int z;
};

class TextArea;

using GDString = std::array<char, 0x18>;
using CCPoint = std::array<float, 2>;

bool TextArea_init(
	TextArea* ecx, GDString stack4, char const* stack1, float xmm2, float xmm3, CCPoint stack5, float stack2, bool stack3
) {
	return true;
}
TEST(MembercallTest, IntoTextAreaInit) {
	auto conv = std::make_unique<MembercallConvention>();
	auto func = AbstractFunction::from(&TextArea_init);
	auto gen = conv->generateIntoDefault(func);
	EXPECT_STREQ(gen.c_str(),
				 "sub esp, 0x38\n"
				 "; 0\n"
				 "mov [esp + 0x0], ecx\n"
				 "; 1\n"
				 "mov eax, [esp + 0x48]\n"
				 "mov [esp + 0x4], eax\n"
				 "mov eax, [esp + 0x4c]\n"
				 "mov [esp + 0x8], eax\n"
				 "mov eax, [esp + 0x50]\n"
				 "mov [esp + 0xc], eax\n"
				 "mov eax, [esp + 0x54]\n"
				 "mov [esp + 0x10], eax\n"
				 "mov eax, [esp + 0x58]\n"
				 "mov [esp + 0x14], eax\n"
				 "mov eax, [esp + 0x5c]\n"
				 "mov [esp + 0x18], eax\n"
				 "; 2\n"
				 "mov eax, [esp + 0x3c]\n"
				 "mov [esp + 0x1c], eax\n"
				 "; 3\n"
				 "movss [esp + 0x20], xmm2\n"
				 "; 4\n"
				 "movss [esp + 0x24], xmm3\n"
				 "; 5\n"
				 "mov eax, [esp + 0x60]\n"
				 "mov [esp + 0x28], eax\n"
				 "mov eax, [esp + 0x64]\n"
				 "mov [esp + 0x2c], eax\n"
				 "; 6\n"
				 "mov eax, [esp + 0x40]\n"
				 "mov [esp + 0x30], eax\n"
				 "; 7\n"
				 "mov eax, [esp + 0x44]\n"
				 "mov [esp + 0x34], eax\n"
	) << prettify(gen);
}
TEST(MembercallTest, CleanupTextAreaInit) {
	auto conv = std::make_unique<MembercallConvention>();
	auto func = AbstractFunction::from(&TextArea_init);
	auto gen = conv->generateDefaultCleanup(func);
	EXPECT_STREQ(gen.c_str(),
				 "add esp, 0x38\n"
				 "ret 0x2c\n"
				 ) << prettify(gen);
}

TextArea* TextArea_create(GDString stack1, char const* ecx, float xmm1, float xmm2, CCPoint stack2, float xmm3, bool edx) {
	return nullptr;
}
TEST(OptcallTest, IntoTextAreaCreate) {
	auto conv = std::make_unique<OptcallConvention>();
	auto func = AbstractFunction::from(&TextArea_create);
	auto gen = conv->generateIntoDefault(func);
	EXPECT_STREQ(gen.c_str(),
				 "sub esp, 0x34\n"
				 "; 0\n"
				 "mov eax, [esp + 0x38]\n"
				 "mov [esp + 0x0], eax\n"
				 "mov eax, [esp + 0x3c]\n"
				 "mov [esp + 0x4], eax\n"
				 "mov eax, [esp + 0x40]\n"
				 "mov [esp + 0x8], eax\n"
				 "mov eax, [esp + 0x44]\n"
				 "mov [esp + 0xc], eax\n"
				 "mov eax, [esp + 0x48]\n"
				 "mov [esp + 0x10], eax\n"
				 "mov eax, [esp + 0x4c]\n"
				 "mov [esp + 0x14], eax\n"
				 "; 1\n"
				 "mov [esp + 0x18], ecx\n"
				 "; 2\n"
				 "movss [esp + 0x1c], xmm1\n"
				 "; 3\n"
				 "movss [esp + 0x20], xmm2\n"
				 "; 4\n"
				 "mov eax, [esp + 0x50]\n"
				 "mov [esp + 0x24], eax\n"
				 "mov eax, [esp + 0x54]\n"
				 "mov [esp + 0x28], eax\n"
				 "; 5\n"
				 "movss [esp + 0x2c], xmm3\n"
				 "; 6\n"
				 "mov [esp + 0x30], edx\n"
	) << prettify(gen);
}
TEST(OptcallTest, CleanupTextAreaCreate) {
	auto conv = std::make_unique<OptcallConvention>();
	auto func = AbstractFunction::from(&TextArea_create);
	auto gen = conv->generateDefaultCleanup(func);
	EXPECT_STREQ(gen.c_str(),
				 "add esp, 0x34\n"
				 "ret\n"
	) << prettify(gen);
}

int optcall0(Big stack1, int ecx, float stack2) {
	assert(stack1.x == 1);
	assert(stack1.y == 2);
	assert(stack1.z == 3);
	assert(ecx == 4);
	assert(stack2 == 5.f);
	return 6;
}
TEST(OptcallTest, IntoBigIntFloat) {
	auto conv = std::make_unique<OptcallConvention>();
	auto func = AbstractFunction::from(&optcall0);
	auto gen = conv->generateIntoDefault(func);
	EXPECT_STREQ(gen.c_str(),
				 "sub esp, 0x14\n"
				 "; 0\n"
				 "mov eax, [esp + 0x18]\n"
				 "mov [esp + 0x0], eax\n"
				 "mov eax, [esp + 0x1c]\n"
				 "mov [esp + 0x4], eax\n"
				 "mov eax, [esp + 0x20]\n"
				 "mov [esp + 0x8], eax\n"
				 "; 1\n"
				 "mov [esp + 0xc], ecx\n"
				 "; 2\n"
				 "movss [esp + 0x10], xmm1\n"
	) << prettify(gen);
}
TEST(OptcallTest, CleanupBigIntFloat) {
	auto conv = std::make_unique<OptcallConvention>();
	auto func = AbstractFunction::from(&optcall0);
	auto gen = conv->generateDefaultCleanup(func);
	EXPECT_STREQ(gen.c_str(),
				 "add esp, 0x14\n"
				 "ret\n"
	) << prettify(gen);
}

int optcall1(Big stack1, int ecx, float stack2, int edx, float stack3) {
	assert(stack1.x == 1);
	assert(stack1.y == 2);
	assert(stack1.z == 3);
	assert(ecx == 4);
	assert(stack2 == 5.f);
	assert(edx == 6);
	assert(stack3 == 7.f);
	return 8;
}
TEST(OptcallTest, IntoBigIntFloatIntFloat) {
	auto conv = std::make_unique<OptcallConvention>();
	auto func = AbstractFunction::from(&optcall1);
	auto gen = conv->generateIntoDefault(func);
	EXPECT_STREQ(gen.c_str(),
				 "sub esp, 0x1c\n"
				 "; 0\n"
				 "mov eax, [esp + 0x20]\n"
				 "mov [esp + 0x0], eax\n"
				 "mov eax, [esp + 0x24]\n"
				 "mov [esp + 0x4], eax\n"
				 "mov eax, [esp + 0x28]\n"
				 "mov [esp + 0x8], eax\n"
				 "; 1\n"
				 "mov [esp + 0xc], ecx\n"
				 "; 2\n"
				 "movss [esp + 0x10], xmm1\n"
				 "; 3\n"
				 "mov [esp + 0x14], edx\n"
				 "; 4\n"
				 "movss [esp + 0x18], xmm3\n"
	) << prettify(gen);
}
TEST(OptcallTest, CleanupBigIntFloatIntFloat) {
	auto conv = std::make_unique<OptcallConvention>();
	auto func = AbstractFunction::from(&optcall1);
	auto gen = conv->generateDefaultCleanup(func);
	EXPECT_STREQ(gen.c_str(),
				 "add esp, 0x1c\n"
				 "ret\n"
	) << prettify(gen);
}

Big optcall2(Big stack1, float stack2, int edx, float stack3) {
	assert(stack1.x == 1);
	assert(stack1.y == 2);
	assert(stack1.z == 3);
	assert(stack2 == 5.f);
	assert(edx == 6);
	assert(stack3 == 7.f);
	return {8, 9, 10};
}
TEST(OptcallTest, IntoFloatIntFloat) {
	auto conv = std::make_unique<OptcallConvention>();
	auto func = AbstractFunction::from(&optcall2);
	auto gen = conv->generateIntoDefault(func);
	EXPECT_STREQ(gen.c_str(),
				 "sub esp, 0x1c\n"
				 "; 0\n"
				 "mov [esp + 0x0], ecx\n"
				 "; 0\n"
				 "mov eax, [esp + 0x20]\n"
				 "mov [esp + 0x4], eax\n"
				 "mov eax, [esp + 0x24]\n"
				 "mov [esp + 0x8], eax\n"
				 "mov eax, [esp + 0x28]\n"
				 "mov [esp + 0xc], eax\n"
				 "; 1\n"
				 "movss [esp + 0x10], xmm0\n"
				 "; 2\n"
				 "mov [esp + 0x14], edx\n"
				 "; 3\n"
				 "movss [esp + 0x18], xmm2\n"
	) << prettify(gen);
}
TEST(OptcallTest, CleanupFloatIntFloat) {
	auto conv = std::make_unique<OptcallConvention>();
	auto func = AbstractFunction::from(&optcall2);
	auto gen = conv->generateDefaultCleanup(func);
	EXPECT_STREQ(gen.c_str(),
				 "add esp, 0x1c\n"
				 "ret\n"
	) << prettify(gen);
}
