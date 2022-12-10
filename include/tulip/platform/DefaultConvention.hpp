#pragma once

#include "../CallingConvention.hpp"

#include <string>

namespace tulip::hook {
	class AbstractFunction;

	class DefaultConvention : public CallingConvention {
	public:
		~DefaultConvention() override;

		std::string generateFromDefault(AbstractFunction const& function) override;
		std::string generateToDefault(AbstractFunction const& function) override;
		std::string generateBackFromDefault(AbstractFunction const& function) override;
		std::string generateBackToDefault(AbstractFunction const& function, size_t stackOffset) override;
	};
}
