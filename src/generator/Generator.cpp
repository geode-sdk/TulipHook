#include "Generator.hpp"

#include "../target/PlatformTarget.hpp"
#include <iostream>
#include <iomanip>

using namespace tulip::hook;

HandlerGenerator::HandlerGenerator(
	void* address, void* trampoline, void* handler, void* content, void* wrapped, HandlerMetadata const& metadata
) :
	m_address(address),
	m_trampoline(trampoline),
	m_handler(handler),
	m_content(content),
	m_wrapped(wrapped),
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

	for (auto i = 0; i < encode.size(); i++) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(encode[i]) << " ";
	}
	std::cout << std::endl;

	return Ok(std::move(encode));
}

Result<> HandlerGenerator::generateTrampoline(RelocateReturn offsets) {
	auto address = reinterpret_cast<uint64_t>(m_trampoline) + offsets.m_trampolineOffset;
	auto encode = this->trampolineBytes(address, offsets.m_originalOffset);

	TULIP_HOOK_UNWRAP(Target::get().writeMemory(reinterpret_cast<void*>(address), encode.data(), encode.size()));

	return Ok();
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