#include <TulipHook.hpp>

#include "Pool.hpp"
#include "Handler.hpp"

using namespace tulip::hook;

HandlerHandle createHandler(void* address, HandlerMetadata metadata) {
	return Pool::get().createHandler(address, metadata);
}

void removeHandler(HandlerHandle const& handler) {
	Pool::get().removeHandler(handler);
}

HookHandle createHook(HandlerHandle const& handler, void* function, HookMetadata metadata) noexcept {
	return Pool::get().getHandler(handler).createHook(function, metadata);
}

void removeHook(HandlerHandle const& handler, HookHandle const& hook) noexcept {
	Pool::get().getHandler(handler).removeHook(hook);
}