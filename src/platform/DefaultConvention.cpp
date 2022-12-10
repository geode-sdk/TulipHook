#include <Platform.hpp>
#include <platform/DefaultConvention.hpp>

using namespace tulip::hook;

DefaultConvention::~DefaultConvention() {}

std::string DefaultConvention::generateFromDefault(AbstractFunction const& function) {
	return "ret";
}

std::string DefaultConvention::generateToDefault(AbstractFunction const& function) {
	return "";
}

std::string DefaultConvention::generateBackFromDefault(AbstractFunction const& function) {
	return "";
}

std::string DefaultConvention::generateBackToDefault(AbstractFunction const& function, size_t stackOffset) {
	return "";
}