#include "Generator.hpp"

#include "../target/PlatformTarget.hpp"

using namespace tulip::hook;

HandlerGenerator::HandlerGenerator(
	void* address, void* trampoline, void* handler, void* content, HandlerMetadata const& metadata
) :
	m_address(address),
	m_trampoline(trampoline),
	m_handler(handler),
	m_content(content),
	m_metadata(metadata) {}

WrapperGenerator::WrapperGenerator(void* address, WrapperMetadata const& metadata) :
	m_address(address),
	m_metadata(metadata) {}

geode::Result<FunctionData> HandlerGenerator::generateHandler() {
	auto address = reinterpret_cast<uint64_t>(m_handler);
	auto encode = this->handlerBytes(address);

	GEODE_UNWRAP(Target::get().writeMemory(m_handler, encode.m_handlerBytes.data(), encode.m_handlerBytes.size()));

	return geode::Ok(FunctionData{m_handler, encode.m_codeSize});
}

geode::Result<std::vector<uint8_t>> HandlerGenerator::generateIntervener(int64_t size) {
	auto address = reinterpret_cast<uint64_t>(m_address);
	auto encode = this->intervenerBytes(address, size);

	return geode::Ok(std::move(encode));
}

geode::Result<HandlerGenerator::GeneratedTrampolineReturn> HandlerGenerator::generateTrampoline(uint64_t target, void const* originalBuffer) {
	GEODE_UNWRAP_INTO(auto encode, this->trampolineBytes(target, originalBuffer));

	GEODE_UNWRAP(Target::get().writeMemory(m_trampoline, encode.m_trampolineBytes.data(), encode.m_trampolineBytes.size()));

	return geode::Ok(GeneratedTrampolineReturn{
		.m_codeSize = encode.m_codeSize,
		.m_originalOffset = encode.m_originalOffset
	});
}

HandlerGenerator::HandlerReturn HandlerGenerator::handlerBytes(uint64_t address) {
	return HandlerReturn{std::vector<uint8_t>(), 0};
}
std::vector<uint8_t> HandlerGenerator::intervenerBytes(uint64_t address, size_t size) {
	return std::vector<uint8_t>();
}
geode::Result<HandlerGenerator::TrampolineReturn> HandlerGenerator::trampolineBytes(uint64_t target, void const* originalBuffer) {
	return geode::Ok(TrampolineReturn{});
}
geode::Result<HandlerGenerator::RelocateReturn> HandlerGenerator::relocatedBytes(uint64_t base, uint64_t target, void const* originalBuffer) {
	return geode::Ok(RelocateReturn{});
}

geode::Result<FunctionData> WrapperGenerator::generateWrapper() {
	return geode::Ok(FunctionData{m_address, 0}); // only windows needs the wrapper
}

geode::Result<FunctionData> WrapperGenerator::generateReverseWrapper() {
	return geode::Ok(FunctionData{m_address, 0}); // only windows needs the wrapper
}

std::vector<uint8_t> WrapperGenerator::wrapperBytes(uint64_t address) {
	return std::vector<uint8_t>();
}

std::vector<uint8_t> WrapperGenerator::reverseWrapperBytes(uint64_t address) {
	return std::vector<uint8_t>();
}