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

Result<> HandlerGenerator::generateHandler() {
	auto address = reinterpret_cast<uint64_t>(m_handler);
	auto encode = this->handlerBytes(address);

	TULIP_HOOK_UNWRAP(Target::get().writeMemory(m_handler, encode.data(), encode.size()));

	return Ok();
}

Result<std::vector<uint8_t>> HandlerGenerator::generateIntervener() {
	auto address = reinterpret_cast<uint64_t>(m_address);
	auto encode = this->intervenerBytes(address);

	return Ok(std::move(encode));
}

Result<> HandlerGenerator::generateTrampoline(uint64_t target) {
	TULIP_HOOK_UNWRAP_INTO(auto offsets, this->relocatedBytes(reinterpret_cast<uint64_t>(m_trampoline), target));

	auto address = reinterpret_cast<uint64_t>(m_trampoline) + offsets.m_relocatedBytes.size();
	auto encode = this->trampolineBytes(address, offsets.m_originalOffset);

	std::vector<uint8_t> merge;
	merge.insert(merge.end(), offsets.m_relocatedBytes.begin(), offsets.m_relocatedBytes.end());
	merge.insert(merge.end(), encode.begin(), encode.end());

	TULIP_HOOK_UNWRAP(Target::get().writeMemory(m_trampoline, merge.data(), merge.size()));

	return Ok();
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
Result<HandlerGenerator::RelocateReturn> HandlerGenerator::relocatedBytes(uint64_t base, uint64_t target) {
	return Ok(HandlerGenerator::RelocateReturn());
}

Result<void*> WrapperGenerator::generateWrapper() {
	return Ok(m_address); // only windows needs the wrapper
}

Result<void*> WrapperGenerator::generateReverseWrapper() {
	return Ok(m_address); // only windows needs the wrapper
}

std::vector<uint8_t> WrapperGenerator::wrapperBytes(uint64_t address) {
	return std::vector<uint8_t>();
}

std::vector<uint8_t> WrapperGenerator::reverseWrapperBytes(uint64_t address) {
	return std::vector<uint8_t>();
}