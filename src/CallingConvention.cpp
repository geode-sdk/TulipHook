#include <CallingConvention.hpp>

using namespace tulip::hook;

CallingConvention::CallingConvention() {
	
}

CallingConvention::~CallingConvention() {

}

~DefaultConvention::DefaultConvention() {

}

std::string DefaultConvention::generateFromDefault(AbstractFunction const& function) override {
	return "";
}
std::string DefaultConvention::generateToDefault(AbstractFunction const& function) override {
	return "";
}