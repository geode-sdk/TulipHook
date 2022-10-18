#include "WindowsGenerator.hpp"
#include "PlatformTarget.hpp"
#include "../Handler.hpp"

#include <sstream>

#include <CallingConvention.hpp>

using namespace tulip::hook;

#if defined(TULIP_HOOK_WINDOWS)

std::string Handler::handlerString() {
	std::ostringstream out;
	out << m_metadata.m_convention->generateToDefault(m_metadata.m_abstract) << "; ";

	// increment and get function
	out << "push esi; push " << m_content << "; call _incrementIndex; push " << m_content << "; call _getNextFunction; ";

	auto count = 0;
	for (auto& param : m_metadata.m_abstract.m_parameters) {
		count += param.m_size;
	}
	if (m_metadata.m_abstract.m_return.m_size > 4 * 2) ++count; // struct return

	// push the stack params
	for (auto i = 0; i < count; ++i) {
		out << "push [esp + " << (i * 4) << "]; ";
	}

	// call cdecl
	out << "call eax; ";

	// fix stack
	out << "add esp, " << (count * 4) << "; ";

	// decrement and return eax and edx
	out << "mov esi, eax; mov edi, edx; call _decrementIndex; mov edx, edi; mov eax, esi; pop esi; ret 0; "

	out << m_metadata.m_convention->generateFromDefault(m_metadata.m_abstract);
	return out.str();
}

#endif