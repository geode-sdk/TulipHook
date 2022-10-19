#include "WindowsGenerator.hpp"
#include "PlatformTarget.hpp"
#include "../Handler.hpp"

#include <sstream>

#include <CallingConvention.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_WINDOWS)

std::string WindowsGenerator::handlerString() {
	std::ostringstream out;
	out << m_metadata.m_convention->generateToDefault(m_metadata.m_abstract) << "; ";

	// increment and get function
	out << "push esi; lea eax, [_content" << m_address << "]; push eax; call _incrementIndex; lea eax, [_content" << m_address << "]; push eax; call _getNextFunction; ";

	auto count = 0;
	for (auto& param : m_metadata.m_abstract.m_parameters) {
		count += (param.m_size + 3) / 4;
	}
	if (m_metadata.m_abstract.m_return.m_size > 4 * 2) ++count; // struct return

	// push the stack params
	for (auto i = 0; i < count; ++i) {
		out << "push [esp + " << ((count + 3) * 4) << "]; ";
	}

	// call cdecl
	out << "call eax; ";

	// fix stack
	out << "add esp, " << ((count + 2) * 4) << "; ";
	

	// decrement and return eax and edx
	out << "mov esi, eax; mov edi, edx; call _decrementIndex; mov edx, edi; mov eax, esi; pop esi; ";

	out << m_metadata.m_convention->generateFromDefault(m_metadata.m_abstract);
	return out.str();
}

#endif