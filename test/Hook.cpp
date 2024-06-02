#include <gtest/gtest.h>

#include <tulip/TulipHook.hpp>

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

TEST(HookTest, NoHandler) {
	EXPECT_EQ(callFunction<0>(), 1);
}

TEST(HookTest, NoHooks) {
	HandlerHandle handlerHandle;
	makeHandler<1>(handlerHandle);
	EXPECT_EQ(callFunction<1>(), 1);
}

TEST(HookTest, MakeWrapper) {
	FunctionPtrType unwrapped;
	makeWrapper<2>(unwrapped);
	// EXPECT_EQ(unwrapped(1, 2, 3, 4, 5, 6, 7, 8, 9, 1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f, 9.0f, 10.0f), 1);
}

// hook -> function
TEST(HookTest, SingleHook) {
	HandlerHandle handlerHandle;
	makeHandler<3>(handlerHandle);

	makeHook<3>(handlerHandle);

	EXPECT_EQ(callFunction<3>(), 3);
}

// priorityHook -> hook -> function
TEST(HookTest, PriorityHook) {
	HandlerHandle handlerHandle;
	makeHandler<4>(handlerHandle);

	makeHook<4>(handlerHandle);
	makePriorityHook<4>(handlerHandle);

	EXPECT_EQ(callFunction<4>(), 6);
}

// priorityHook -> function
TEST(HookTest, RemoveHook) {
	HandlerHandle handlerHandle;
	makeHandler<5>(handlerHandle);

	HookHandle hookHandle = makeHook<5>(handlerHandle);
	makePriorityHook<5>(handlerHandle);
	removeHook(handlerHandle, hookHandle);

	EXPECT_EQ(callFunction<5>(), 4);
}

// priorityHook -> hook -> function
TEST(HookTest, ReAddHook) {
	HandlerHandle handlerHandle;
	makeHandler<6>(handlerHandle);

	HookHandle hookHandle = makeHook<6>(handlerHandle);
	makePriorityHook<6>(handlerHandle);
	removeHook(handlerHandle, hookHandle);
	makeHook<6>(handlerHandle);

	EXPECT_EQ(callFunction<6>(), 6);
}

// priorityHook -> priorityHook -> priorityHook -> function
TEST(HookTest, MultiInstance) {
	HandlerHandle handlerHandle;
	makeHandler<7>(handlerHandle);

	makePriorityHook<7>(handlerHandle);
	makePriorityHook<7>(handlerHandle);
	makePriorityHook<7>(handlerHandle);

	EXPECT_EQ(callFunction<7>(), 10);
}

// priorityHook -> priorityHook -> priorityHook -> priorityHook -> hook -> function
TEST(HookTest, MoreMultiInstance) {
	HandlerHandle handlerHandle;
	makeHandler<8>(handlerHandle);

	makeHook<8>(handlerHandle);
	makePriorityHook<8>(handlerHandle);
	makePriorityHook<8>(handlerHandle);
	makePriorityHook<8>(handlerHandle);
	makePriorityHook<8>(handlerHandle);

	EXPECT_EQ(callFunction<8>(), 15);
}

TEST(HookTest, RemoveHandler) {
	HandlerHandle handlerHandle;
	makeHandler<9>(handlerHandle);

	makeHook<9>(handlerHandle);

	destroyHandler(handlerHandle);

	EXPECT_EQ(callFunction<9>(), 1);
}

TEST(HookTest, RecreateHandler) {
	HandlerHandle handlerHandle;
	makeHandler<10>(handlerHandle);

	makeHook<10>(handlerHandle);

	destroyHandler(handlerHandle);

	makeHandler<10>(handlerHandle);

	EXPECT_EQ(callFunction<10>(), 1);
}
