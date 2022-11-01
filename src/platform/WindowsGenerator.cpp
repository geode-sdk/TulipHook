#include "WindowsGenerator.hpp"
#include "PlatformTarget.hpp"
#include "../Handler.hpp"

#include <sstream>

#include <CallingConvention.hpp>
#include <iostream>

using namespace tulip::hook;

#if defined(TULIP_HOOK_WINDOWS)

std::string WindowsGenerator::handlerString() {
	std::ostringstream out;
	out << std::hex;
	out << m_metadata.m_convention->generateToDefault(m_metadata.m_abstract) << "; ";

	// increment and get function
	out <<
		"push esi; "
		"lea eax, [_content" << m_address << "]; "
		"push eax; "
		"call _incrementIndex; "
		"lea eax, [_content" << m_address << "]; "
		"push eax; "
		"call _getNextFunction; ";

	size_t stackSize = 0;
	for (auto& param : m_metadata.m_abstract.m_parameters) {
		stackSize += (param.m_size + 3) / 4 * 4;
	}
	// struct return
	if (m_metadata.m_abstract.m_return.m_size > 4 * 2) {
		stackSize += 4;
	}

	// push the stack params
	for (size_t i = 0; i < stackSize; i += 4) {
		out << "push [esp + 0x" << (stackSize + 8) << "]; ";
	}

	// call cdecl
	out << "call eax; ";

	// fix stack
	out << "add esp, 0x" << stackSize << "; ";
	
	// decrement and return eax and edx
	out << 
		"mov esi, eax; "
		"mov edi, edx; "
		"call _decrementIndex; "
		"mov edx, edi; "
		"mov eax, esi; "
		"pop esi; ";

	out << m_metadata.m_convention->generateFromDefault(m_metadata.m_abstract);
	return out.str();
}

std::string WindowsGenerator::trampolineString(size_t offset) {
	std::ostringstream out;
	out << m_metadata.m_convention->generateBackToDefault(m_metadata.m_abstract, 0x8) << "; ";
	out << "jmp _address" << m_address << "_" << offset;
	return out.str();
}

#endif
