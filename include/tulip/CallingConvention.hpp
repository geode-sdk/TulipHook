#pragma once

#include <string>

namespace tulip::hook {
	class AbstractFunction;

	class CallingConvention {
	public:
		virtual ~CallingConvention() = 0;

		virtual std::string generateFromDefault(AbstractFunction const& function) = 0;
		virtual std::string generateToDefault(AbstractFunction const& function) = 0;
		virtual std::string generateBackToDefault(AbstractFunction const& function, size_t stackOffset) = 0;
		virtual std::string generateBackFromDefault(AbstractFunction const& function) = 0;
	};
}
