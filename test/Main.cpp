#include <TulipHook.hpp>
#include <iostream>
#include <cassert>

int32_t function(int a, int b, int c, int d, int e, int f, int g, int h, int i) {
	std::cout << "function called!\n" 
	<< a << " " 
	<< b << " " 
	<< c << " " 
	<< d << " " 
	<< e << " " 
	<< f << " " 
	<< g << " " 
	<< h << " " 
	<< i << " \n";

	return 1;
}

int32_t hook(int a, int b, int c, int d, int e, int f, int g, int h, int i) {
	std::cout << "hook begin!\n";
	auto ret = function(a, b, c, d, e, f, g, h, i);
	std::cout << "hook end!\n";

	return 3;
}

int32_t priorityHook(int a, int b, int c, int d, int e, int f, int g, int h, int i) {
	std::cout << "priority hook begin!\n";
	auto ret = function(a, b, c, d, e, f, g, h, i);
	std::cout << "priority hook end!\n";

	return ret + 3;
}

using namespace tulip::hook;

HandlerHandle makeHandler() {
	std::cout << "\nmakeHandler\n";
	HandlerMetadata handlerMetadata;
	handlerMetadata.m_convention = std::make_unique<PlatformConvention>();
	handlerMetadata.m_abstract = AbstractFunction::from<int32_t(int, int, int, int, int, int, int, int, int)>();

	auto handle = createHandler(reinterpret_cast<void*>(&function), std::move(handlerMetadata));

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

	auto handle2 = createHook(handle, reinterpret_cast<void*>(&hook), std::move(metadata));

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

	auto handle2 = createHook(handle, reinterpret_cast<void*>(&priorityHook), std::move(metadata));

	std::cout << "\nmakePriorityHook end\n";

	return handle2;
}

void destroyPriorityHook(HandlerHandle const& handle, HookHandle const& handle2) {
	std::cout << "\ndestroyPriorityHook\n";
	removeHook(handle, handle2);

	std::cout << "\ndestroyPriorityHook end\n";
}

int callFunction() {
	return function(1, 2, 3, 4, 5, 6, 7, 8, 9);
}


int main() {
	// No handler
	assert(callFunction() == 1);

	// Handler, no hooks
	HandlerHandle handlerHandle = makeHandler();
	assert(callFunction() == 1);

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