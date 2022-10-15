#include "../Handler.hpp"
#include <Platform.hpp>
#include "../Pool.hpp"
#include <CallingConvention.hpp>

#include <sstream>

using namespace tulip::hook;

/* 
ret defaultConv handler(params) {

	incrementIndex(address);

	void* func = getNextFunction(content);
	ret = func(params);

	decrementIndex();

	return ret;
}
*/ 

#if defined(TULIP_HOOK_MACOS)

std::string Handler::handlerString() {
	std::ostringstream out;
	out << m_metadata.m_convention->generateToDefault(m_metadata.m_abstract) << ";";

	// add asm handler

	out << ";" << m_metadata.m_convention->generateFromDefault(m_metadata.m_abstract);
	return out.str();
}
std::string Handler::intervenerString() {
	std::ostringstream out;
	out << "jmp _handler" << m_address;
	return out.str();
}

#endif