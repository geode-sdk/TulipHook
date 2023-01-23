#include <Platform.hpp>
#include <platform/DefaultConvention.hpp>

using namespace tulip::hook;

DefaultConvention::~DefaultConvention() {}

std::string DefaultConvention::generateDefaultCleanup(AbstractFunction const& function) {
	return "ret";
}

std::string DefaultConvention::generateIntoDefault(AbstractFunction const& function) {
	return "";
}

std::string DefaultConvention::generateIntoOriginal(AbstractFunction const& function) {
	return "";
}

std::string DefaultConvention::generateOriginalCleanup(AbstractFunction const& function) {
	return "ret";
}

std::shared_ptr<DefaultConvention> DefaultConvention::create() {
	return std::make_shared<DefaultConvention>();
}
