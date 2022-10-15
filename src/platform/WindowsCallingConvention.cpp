#include <platform/WindowsCallingConvention.hpp>

#if defined(TULIP_HOOK_WINDOWS)

std::string CdeclConvention::generateFromDefault(AbstractFunction const& function) override {
	return "";
}
std::string CdeclConvention::generateToDefault(AbstractFunction const& function) override {
	return "";
}

std::string ThiscallConvention::generateFromDefault(AbstractFunction const& function) override {
	return "";
}
std::string ThiscallConvention::generateToDefault(AbstractFunction const& function) override {
	return "";
}

std::string OptcallConvention::generateFromDefault(AbstractFunction const& function) override {
	return "";
}
std::string OptcallConvention::generateToDefault(AbstractFunction const& function) override {
	return "";
}

std::string MembercallConvention::generateFromDefault(AbstractFunction const& function) override {
	return "";
}
std::string MembercallConvention::generateToDefault(AbstractFunction const& function) override {
	return "";
}

#endif