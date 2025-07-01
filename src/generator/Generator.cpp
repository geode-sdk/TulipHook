#include "Generator.hpp"

#include "../target/PlatformTarget.hpp"

using namespace tulip::hook;

// virtual std::vector<uint8_t> handlerBytes(int64_t handler, void* content, HandlerMetadata const& metadata);
// virtual std::vector<uint8_t> intervenerBytes(int64_t original, int64_t handler, size_t size);
// virtual geode::Result<RelocateReturn> relocatedBytes(int64_t original, int64_t relocated, size_t size);
// virtual std::vector<uint8_t> wrapperBytes(int64_t original, int64_t wrapper);
// virtual std::vector<uint8_t> commonHandlerBytes(int64_t handler, ptrdiff_t spaceOffset);
// virtual std::vector<uint8_t> commonIntervenerBytes(int64_t original, int64_t handler, size_t unique, ptrdiff_t relocOffset);

BaseGenerator::HandlerReturn BaseGenerator::handlerBytes(int64_t original, int64_t handler, void* content, HandlerMetadata const& metadata) {
	return HandlerReturn{ std::vector<uint8_t>(), nullptr };
}

std::vector<uint8_t> BaseGenerator::intervenerBytes(int64_t original, int64_t handler, size_t size) {
	return std::vector<uint8_t>();
}

geode::Result<BaseGenerator::RelocateReturn> BaseGenerator::relocatedBytes(int64_t original, int64_t relocated, std::span<uint8_t const> originalBuffer, size_t targetSize) {
	return geode::Ok(RelocateReturn{ std::vector<uint8_t>(), 0 });
}

BaseGenerator::WrapperReturn BaseGenerator::wrapperBytes(int64_t original, int64_t wrapper, WrapperMetadata const& metadata) {
	return WrapperReturn{ std::vector<uint8_t>(), nullptr };
}

std::vector<uint8_t> BaseGenerator::runtimeInfoBytes(int64_t function, size_t size, int64_t push, int64_t move, int64_t alloc) {
	return std::vector<uint8_t>();
}

std::vector<uint8_t> BaseGenerator::commonHandlerBytes(int64_t handler, ptrdiff_t spaceOffset) {
	return std::vector<uint8_t>();
}

std::vector<uint8_t> BaseGenerator::commonIntervenerBytes(int64_t original, int64_t handler, size_t unique, ptrdiff_t relocOffset) {
	return std::vector<uint8_t>();
}