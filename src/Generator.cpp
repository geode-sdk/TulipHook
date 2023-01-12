#include "Generator.hpp"

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