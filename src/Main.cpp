#include <TulipHook.hpp>

using namespace tulip::hook;

HandlerHandle createHandler(void* address, HandlerMetadata&& metadata, std::error_code& error) noexcept {

}
HandlerHandle createHandler(void* address, HandlerMetadata&& metadata) {
	auto error = std::error_code();

	auto handler = createHandler(address, std::forward<HookMetadata>(metadata), error);

	if (error) throw error.value();
	return handler;
}

void removeHandler(HandlerHandle const& handler, std::error_code& error) noexcept {

}
void removeHandler(HandlerHandle const& handler) {
	auto error = std::error_code();

	removeHandler(address, error);

	if (error) throw error.value();
}

HookHandle createHook(HandlerHandle const& handler, void* function, HookMetadata&& metadata, std::error_code& error) noexcept {

}
HookHandle createHook(HandlerHandle const& handler, void* function, HookMetadata&& metadata) noexcept {
	auto error = std::error_code();

	auto hook = addHook(handler, function, std::forward<HookMetadata>(metadata), error);

	if (error) throw error.value();
	return hook;
}

void removeHook(HookHandle const& hook, std::error_code& error) noexcept {

}
void removeHook(HookHandle const& hook) noexcept {
	auto error = std::error_code();

	removeHook(hook, error);

	if (error) throw error.value();
}