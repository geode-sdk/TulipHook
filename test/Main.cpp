#include <TulipHook.hpp>
#include <iostream>

int32_t function() {
	std::cout << "function called!\n";

	return 1;
}

int32_t hook() {
	std::cout << "hook begin!\n";
	auto ret = function();
	std::cout << "hook end!\n";

	return 3;
}

int32_t priorityHook() {
	std::cout << "priority hook begin!\n";
	auto ret = function();
	std::cout << "priority hook end!\n";

	return ret + 3;
}

using namespace tulip::hook;

HandlerHandle makeHandler() {
	std::error_code error;

	HandlerMetadata metadata;
	metadata.m_convention = std::make_unique<DefaultConvention>();

	auto handle = createHandler(reinterpret_cast<void*>(&function), std::move(metadata), error);
	assert(!error);

	return handle;
}

void destroyHandler(HandlerHandle const& handle) {
	std::error_code error;

	removeHandler(handle, error);
	assert(!error);
}

HookHandle makeHook() {
	std::error_code error;

	HookMetadata metadata;

	auto handle = createHandler(reinterpret_cast<void*>(&hook), std::move(metadata), error);
	assert(!error);

	return handle;
}

void destroyHook(HookHandle const& handle) {
	std::error_code error;

	removeHook(handle, error);
	assert(!error);
}

HookHandle makePriorityHook() {
	std::error_code error;

	HookMetadata metadata;
	metadata.m_priority = -1;

	auto handle = createHandler(reinterpret_cast<void*>(&hook), std::move(metadata), error);
	assert(!error);

	return handle;
}

void destroyPriorityHook(HookHandle const& handle) {
	std::error_code error;

	removeHook(handle, error);
	assert(!error);
}

int main() {
	// No handler
	assert(function() == 1);

	// Handler, no hooks
	HandlerHandle handlerHandle = makeHandler();
	assert(function() == 1);

	// Single hook (hook -> function)
	HookHandle hookHandle = makeHook();
	assert(function() == 3);

	// Priority hook (priorityHook -> hook -> function)
	HookHandle priorityHookHandle = makePriorityHook();
	assert(function() == 6);

	// Remove the hook (priorityHook -> function)
	destroyHook(hookHandle);
	assert(function() == 4);

	// Readd the hook (priorityHook -> hook -> function)
	hookHandle = makeHook();
	assert(function() == 6);

	// Remove the handler
	destroyHandler(handlerHandle);
	assert(function() == 1);
}