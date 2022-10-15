#include <CallingConvention.hpp>

using namespace tulip::hook;

CallingConvention::CallingConvention() {
	
}

CallingConvention::~CallingConvention() {

}

DefaultConvention::~DefaultConvention() {

}

std::string DefaultConvention::generateFromDefault(AbstractFunction const& function) {
	return "";
}
std::string DefaultConvention::generateToDefault(AbstractFunction const& function) {
	return "";
}

std::string CallingConvention::generateFromDefault(AbstractFunction const& function) {
	return "";
}
std::string CallingConvention::generateToDefault(AbstractFunction const& function) {
	return "";
}