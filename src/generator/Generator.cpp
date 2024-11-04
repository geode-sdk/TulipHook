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

	GEODE_UNWRAP(Target::get().writeMemory(m_handler, encode.data(), encode.size()));

	return geode::Ok(FunctionData{m_handler, encode.size()});
}

geode::Result<std::vector<uint8_t>> HandlerGenerator::generateIntervener() {
	auto address = reinterpret_cast<uint64_t>(m_address);
	auto encode = this->intervenerBytes(address);

	return geode::Ok(std::move(encode));
}

geode::Result<FunctionData> HandlerGenerator::generateTrampoline(uint64_t target) {
	GEODE_UNWRAP_INTO(auto offsets, this->relocatedBytes(reinterpret_cast<uint64_t>(m_trampoline), target));

	auto address = reinterpret_cast<uint64_t>(m_trampoline) + offsets.m_relocatedBytes.size();
	auto encode = this->trampolineBytes(address, offsets.m_originalOffset);

	std::vector<uint8_t> merge;
	merge.insert(merge.end(), offsets.m_relocatedBytes.begin(), offsets.m_relocatedBytes.end());
	merge.insert(merge.end(), encode.begin(), encode.end());

	GEODE_UNWRAP(Target::get().writeMemory(m_trampoline, merge.data(), merge.size()));

	return geode::Ok(FunctionData{m_trampoline, merge.size()});
}

std::vector<uint8_t> HandlerGenerator::handlerBytes(uint64_t address) {
	return std::vector<uint8_t>();
}
std::vector<uint8_t> HandlerGenerator::intervenerBytes(uint64_t address) {
	return std::vector<uint8_t>();
}
std::vector<uint8_t> HandlerGenerator::trampolineBytes(uint64_t address, size_t offset) {
	return std::vector<uint8_t>();
}
geode::Result<HandlerGenerator::RelocateReturn> HandlerGenerator::relocatedBytes(uint64_t base, uint64_t target) {
	return geode::Ok(HandlerGenerator::RelocateReturn());
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