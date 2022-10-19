#include "Generator.hpp"

using namespace tulip::hook;

Generator::Generator(void* address, void* trampoline, void* handler, void* content, HandlerMetadata metadata) 
	: m_address(address), m_trampoline(trampoline), m_handler(handler), m_content(content), m_metadata(metadata) {

}