#include <gtest/gtest.h>

#include <tulip/TulipHook.hpp>
#include <iostream>
#include <cstdint>

#define FUNCTION_PARAM_TYPES int, int, int, int, int, int, int, int, int, float, float, float, float, float, float, float, float, float, float

template <int N>
int32_t function(FUNCTION_PARAM_TYPES) {
	return 1;
}

template <int N>
int32_t hook(FUNCTION_PARAM_TYPES) {
	return 3;
}

template <int N, class... Params>
int32_t priorityHook(Params... params) {
	auto ret = function<N>(params...);
	return ret + 3;
}

using namespace tulip::hook;

using FunctionPtrType = int32_t (*)(
	FUNCTION_PARAM_TYPES
);

template <int N>
void makeWrapper(FunctionPtrType& out) {
	WrapperMetadata wrapperMetadata;
	wrapperMetadata.m_convention = std::make_unique<PlatformConvention>();
	wrapperMetadata.m_abstract = AbstractFunction::from<std::remove_pointer_t<FunctionPtrType>>();

	auto wrapped =
		createWrapper(reinterpret_cast<void*>(static_cast<FunctionPtrType>(&function<N>)), wrapperMetadata);

	ASSERT_FALSE(wrapped.isErr()) << "Failed to create wrapper: " << wrapped.unwrapErr();

	out = reinterpret_cast<FunctionPtrType>(wrapped.unwrap());

	auto ret = out(1, 2, 3, 4, 5, 6, 7, 8, 9, 1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f, 9.0f, 10.0f);
	EXPECT_EQ(ret, 1);
}

template <int N>
void makeHandler(HandlerHandle& out) {
	HandlerMetadata handlerMetadata;
	handlerMetadata.m_convention = std::make_unique<PlatformConvention>();
	handlerMetadata.m_abstract = AbstractFunction::from<int32_t(
		int, int, int, int, int, int, int, int, int, float, float, float, float, float, float, float, float, float, float
	)>();

	auto handle =
		createHandler(reinterpret_cast<void*>(static_cast<FunctionPtrType>(&function<N>)), handlerMetadata);

	ASSERT_FALSE(handle.isErr()) << "Failed to create handler: " << handle.unwrapErr();

	out = handle.unwrap();
}

void destroyHandler(HandlerHandle const& handle) {
	auto rem = removeHandler(handle);
	if (rem.isErr())
		exit(1);
}

template <int N>
HookHandle makeHook(HandlerHandle const& handle) {
	HookMetadata metadata;
	return createHook(handle, reinterpret_cast<void*>(static_cast<FunctionPtrType>(&hook<N>)), metadata);
}

template <int N>
HookHandle makePriorityHook(HandlerHandle const& handle) {
	HookMetadata metadata;
	metadata.m_priority = -100;
	return createHook(handle, reinterpret_cast<void*>(static_cast<FunctionPtrType>(&priorityHook<N, FUNCTION_PARAM_TYPES>)), metadata);
}

#pragma clang diagnostic push
#pragma ide diagnostic ignored "ConstantFunctionResult"
template <int N>
int callFunction() {
	return function<N>(1, 2, 3, 4, 5, 6, 7, 8, 9, 1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f, 9.0f, 10.0f);
}
#pragma clang diagnostic pop



class HookTest : public testing::Test {
protected:
	HookTest() {
		setLogCallback([](const auto& str) {
			std::cout << str << std::endl;
		});
	}

	~HookTest() {
		setLogCallback(nullptr);
	}
};

TEST_F(HookTest, NoHandler) {
	EXPECT_EQ(callFunction<0>(), 1);
}

TEST_F(HookTest, NoHooks) {
	HandlerHandle handlerHandle;
	makeHandler<1>(handlerHandle);
	EXPECT_EQ(callFunction<1>(), 1);
}

TEST_F(HookTest, MakeWrapper) {
	FunctionPtrType unwrapped;
	makeWrapper<2>(unwrapped);
	EXPECT_EQ(unwrapped(1, 2, 3, 4, 5, 6, 7, 8, 9, 1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f, 9.0f, 10.0f), 1);
}

// hook -> function
TEST_F(HookTest, SingleHook) {
	HandlerHandle handlerHandle;
	makeHandler<3>(handlerHandle);

	makeHook<3>(handlerHandle);

	EXPECT_EQ(callFunction<3>(), 3);
}

// priorityHook -> hook -> function
TEST_F(HookTest, PriorityHook) {
	HandlerHandle handlerHandle;
	makeHandler<4>(handlerHandle);

	makeHook<4>(handlerHandle);
	makePriorityHook<4>(handlerHandle);

	EXPECT_EQ(callFunction<4>(), 6);
}

// priorityHook -> function
TEST_F(HookTest, RemoveHook) {
	HandlerHandle handlerHandle;
	makeHandler<5>(handlerHandle);

	HookHandle hookHandle = makeHook<5>(handlerHandle);
	makePriorityHook<5>(handlerHandle);
	removeHook(handlerHandle, hookHandle);

	EXPECT_EQ(callFunction<5>(), 4);
}

// priorityHook -> hook -> function
TEST_F(HookTest, ReAddHook) {
	HandlerHandle handlerHandle;
	makeHandler<6>(handlerHandle);

	HookHandle hookHandle = makeHook<6>(handlerHandle);
	makePriorityHook<6>(handlerHandle);
	removeHook(handlerHandle, hookHandle);
	makeHook<6>(handlerHandle);

	EXPECT_EQ(callFunction<6>(), 6);
}

// priorityHook -> priorityHook -> priorityHook -> function
TEST_F(HookTest, MultiInstance) {
	HandlerHandle handlerHandle;
	makeHandler<7>(handlerHandle);

	makePriorityHook<7>(handlerHandle);
	makePriorityHook<7>(handlerHandle);
	makePriorityHook<7>(handlerHandle);

	EXPECT_EQ(callFunction<7>(), 10);
}

// priorityHook -> priorityHook -> priorityHook -> priorityHook -> hook -> function
TEST_F(HookTest, MoreMultiInstance) {
	HandlerHandle handlerHandle;
	makeHandler<8>(handlerHandle);

	makeHook<8>(handlerHandle);
	makePriorityHook<8>(handlerHandle);
	makePriorityHook<8>(handlerHandle);
	makePriorityHook<8>(handlerHandle);
	makePriorityHook<8>(handlerHandle);

	EXPECT_EQ(callFunction<8>(), 15);
}

TEST_F(HookTest, RemoveHandler) {
	HandlerHandle handlerHandle;
	makeHandler<9>(handlerHandle);

	makeHook<9>(handlerHandle);

	destroyHandler(handlerHandle);

	EXPECT_EQ(callFunction<9>(), 1);
}

TEST_F(HookTest, RecreateHandler) {
	HandlerHandle handlerHandle;
	makeHandler<10>(handlerHandle);

	makeHook<10>(handlerHandle);

	destroyHandler(handlerHandle);

	makeHandler<10>(handlerHandle);

	EXPECT_EQ(callFunction<10>(), 1);
}

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

int checkParamsHook(int a, int b, int c, int d, int e, int f, int g, float h, int i, int j, int k, int l, int m, int n, int o, int p, int q, int r, int s) {
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
	return checkParams(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s) + 1;
}

TEST_F(HookTest, SingleHookCheckParams) {
	HandlerMetadata handlerMetadata;
	handlerMetadata.m_convention = std::make_unique<PlatformConvention>();
	handlerMetadata.m_abstract = AbstractFunction::from(&checkParams);

	auto handleRes = createHandler(reinterpret_cast<void*>(&checkParams), handlerMetadata);

	ASSERT_FALSE(handleRes.isErr()) << "Failed to create handler: " << handleRes.unwrapErr();

	auto handle = handleRes.unwrap();

	HookMetadata metadata;
	createHook(handle, reinterpret_cast<void*>(&checkParamsHook), metadata);

	// hook->original
	EXPECT_EQ(checkParams(1, 2, 3, 4, 5, 6, 7, 8.0f, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19), 12);
}

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

int checkStructParamsHook(int a, CheckParamsStruct s) {
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

	return checkStructParams(a, s) + 1;
}

TEST_F(HookTest, SingleHookCheckStructParams) {
#if defined(TULIP_HOOK_X64) && defined(TULIP_HOOK_SYSTEMV_CONV)
	GTEST_SKIP() << "test fails on x64 SysV :(";
#endif

	HandlerMetadata handlerMetadata;
	handlerMetadata.m_convention = std::make_unique<PlatformConvention>();
	handlerMetadata.m_abstract = AbstractFunction::from(&checkStructParams);

	auto handleRes = createHandler(reinterpret_cast<void*>(&checkStructParams), handlerMetadata);

	ASSERT_FALSE(handleRes.isErr()) << "Failed to create handler: " << handleRes.unwrapErr();

	auto handle = handleRes.unwrap();

	HookMetadata metadata;
	createHook(handle, reinterpret_cast<void*>(&checkStructParamsHook), metadata);

	// hook->original
	EXPECT_EQ(checkStructParams(-1, {
		1,
		2,
		3,
		4,
		123456789.1234,
		6,
		7,
		8.0f,
		9,
		10,
		11,
		12,
		123456789123456789ll,
		14,
		15,
		16,
		17,
		18,
		19
	}), 5);
}
