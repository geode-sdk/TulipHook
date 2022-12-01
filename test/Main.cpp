#include <TulipHook.hpp>
#include <iostream>
#include <cassert>

template <class... Params>
int32_t function(Params... params) {
	std::cout << "function called!\n";
	((std::cout << params << " "), ...);
	std::cout << " \n";

	return 1;
}

template <class... Params>
int32_t hook(Params... params) {
	std::cout << "hook begin!\n";
	auto ret = function(params...);
	std::cout << "hook end!\n";

	return 3;
}

template <class... Params>
int32_t priorityHook(Params... params) {
	std::cout << "priority hook begin!\n";
	auto ret = function(params...);
	std::cout << "priority hook end!\n";

	return ret + 3;
}

using namespace tulip::hook;

using FunctionPtrType = int32_t(*)(
	int, int, int, int, int, int, 
	int, int, int,
	float, float, float, float, float, float, float, float,
	float, float
);

HandlerHandle makeHandler() {
	std::cout << "\nmakeHandler\n";
	HandlerMetadata handlerMetadata;
	handlerMetadata.m_convention = std::make_unique<PlatformConvention>();
	handlerMetadata.m_abstract = AbstractFunction::from<
		int32_t(
			int, int, int, int, int, int, 
			int, int, int,
			float, float, float, float, float, float, float, float,
			float, float
		)
	>();

	auto handle = createHandler(reinterpret_cast<void*>(static_cast<FunctionPtrType>(&function)), std::move(handlerMetadata));

	std::cout << "\nmakeHandler end\n";

	return handle;
}

void destroyHandler(HandlerHandle const& handle) {
	std::cout << "\ndestroyHandler\n";
	removeHandler(handle);

	std::cout << "\ndestroyHandler end\n";
}

HookHandle makeHook(HandlerHandle const& handle) {
	std::cout << "\nmakeHook\n";
	HookMetadata metadata;

	auto handle2 = createHook(handle, reinterpret_cast<void*>(static_cast<FunctionPtrType>(&hook)), std::move(metadata));

	std::cout << "\nmakeHook end\n";

	return handle2;
}

void destroyHook(HandlerHandle const& handle, HookHandle const& handle2) {
	std::cout << "\ndestroyHook\n";
	removeHook(handle, handle2);

	std::cout << "\ndestroyHook end\n";
}

HookHandle makePriorityHook(HandlerHandle const& handle) {
	std::cout << "\nmakePriorityHook\n";
	HookMetadata metadata;
	metadata.m_priority = -100;

	auto handle2 = createHook(handle, reinterpret_cast<void*>(static_cast<FunctionPtrType>(&priorityHook)), std::move(metadata));

	std::cout << "\nmakePriorityHook end\n";

	return handle2;
}

void destroyPriorityHook(HandlerHandle const& handle, HookHandle const& handle2) {
	std::cout << "\ndestroyPriorityHook\n";
	removeHook(handle, handle2);

	std::cout << "\ndestroyPriorityHook end\n";
}

int callFunction() {
	return function(
		1, 2, 3, 4, 5, 6, 
		7, 8, 9, 
		1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f, 
		9.0f, 10.0f
	);
}


int main() {
	// No handler
	assert(callFunction() == 1);

	// Handler, no hooks
	HandlerHandle handlerHandle = makeHandler();
	int a;
	// std::cin >> a;

	assert(callFunction() == 1);

	// std::cin >> a;

	// Single hook (hook -> function)
	HookHandle hookHandle = makeHook(handlerHandle);
	assert(callFunction() == 3);

	// Priority hook (priorityHook -> hook -> function)
	HookHandle priorityHookHandle = makePriorityHook(handlerHandle);
	assert(callFunction() == 6);

	// Remove the hook (priorityHook -> function)
	destroyHook(handlerHandle, hookHandle);
	assert(callFunction() == 4);

	// Readd the hook (priorityHook -> hook -> function)
	hookHandle = makeHook(handlerHandle);
	assert(callFunction() == 6);

	// Remove the handler
	destroyHandler(handlerHandle);
	assert(callFunction() == 1);

	// Recreate the handler
	HandlerHandle handlerHandle2 = makeHandler();
	assert(callFunction() == 1);
}