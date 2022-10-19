#include <platform/WindowsConvention.hpp>
#include <Platform.hpp>
#include <AbstractFunction.hpp>

#include <sstream>

using namespace tulip::hook;

#if defined(TULIP_HOOK_WINDOWS)

size_t countFromFunction(AbstractFunction const& function) {
	auto count = 0;
	for (auto& param : function.m_parameters) {
		count += (param.m_size + 3) / 4;
	}
	if (function.m_return.m_size > 4 * 2) ++count; // struct return

	return count;
}

std::string CdeclConvention::generateFromDefault(AbstractFunction const& function) {
	return "ret 0";
}
std::string CdeclConvention::generateToDefault(AbstractFunction const& function) {
	return "";
}
CdeclConvention::~CdeclConvention() {}

std::string ThiscallConvention::generateFromDefault(AbstractFunction const& function) {
	auto count = countFromFunction(function);
	std::ostringstream out;

	out << "add esp, " << (count * 4) << "; ";
	out << "ret " << ((count - 1) * 4);

	return out.str();
}
std::string ThiscallConvention::generateToDefault(AbstractFunction const& function) {
	auto count = countFromFunction(function);
	std::ostringstream out;

	for (auto i = 1; i < count; ++i) {
		out << "push [esp + " << ((count - 1) * 4) << "]; ";
	}
	if (count > 0) out << "push ecx ";

	return out.str();
}
ThiscallConvention::~ThiscallConvention() {}

std::string FastcallConvention::generateFromDefault(AbstractFunction const& function) {
	auto count = countFromFunction(function);
	std::ostringstream out;

	out << "add esp, " << (count * 4) << "; ";
	out << "ret " << ((count - 2) * 4);

	return out.str();
}
std::string FastcallConvention::generateToDefault(AbstractFunction const& function) {
	auto count = countFromFunction(function);
	std::ostringstream out;

	for (auto i = 2; i < count; ++i) {
		out << "push [esp + " << ((count - 2) * 4) << "]; ";
	}
	if (count > 1) out << "push edx; ";
	if (count > 0) out << "push ecx ";

	return out.str();
}
FastcallConvention::~FastcallConvention() {}

std::string OptcallConvention::generateFromDefault(AbstractFunction const& function) {
	return "";
}
std::string OptcallConvention::generateToDefault(AbstractFunction const& function) {
	return "";
}
OptcallConvention::~OptcallConvention() {}

std::string MembercallConvention::generateFromDefault(AbstractFunction const& function) {
	return "";
}
std::string MembercallConvention::generateToDefault(AbstractFunction const& function) {
	return "";
}
MembercallConvention::~MembercallConvention() {}

#endif