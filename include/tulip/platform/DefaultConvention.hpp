#pragma once

#include "../CallingConvention.hpp"

#include <string>

namespace tulip::hook {
	class AbstractFunction;

	class DefaultConvention : public CallingConvention {
	public:
		~DefaultConvention() override;

		std::string generateDefaultCleanup(AbstractFunction const& function) override;
		std::string generateIntoDefault(AbstractFunction const& function) override;
		std::string generateIntoOriginal(AbstractFunction const& function) override;
		std::string generateOriginalCleanup(AbstractFunction const& function) override;
	};
}
