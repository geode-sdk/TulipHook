#include <TulipHook.hpp>

#include "Pool.hpp"
#include "Handler.hpp"

using namespace tulip::hook;

HandlerHandle tulip::hook::createHandler(void* address, HandlerMetadata metadata) {
	return Pool::get().createHandler(address, metadata);
}

void tulip::hook::removeHandler(HandlerHandle const& handler) {
	Pool::get().removeHandler(handler);
}

HookHandle tulip::hook::createHook(HandlerHandle const& handler, void* function, HookMetadata metadata) noexcept {
	return Pool::get().getHandler(handler).createHook(function, metadata);
}

void tulip::hook::removeHook(HandlerHandle const& handler, HookHandle const& hook) noexcept {
	Pool::get().getHandler(handler).removeHook(hook);
}