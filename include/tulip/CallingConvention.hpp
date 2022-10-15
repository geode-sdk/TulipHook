#pragma once

#include <string>

namespace tulip::hook {
	class AbstractFunction;

	class CallingConvention {
	public:
		CallingConvention();
		virtual ~CallingConvention() = 0;

		virtual std::string generateFromDefault(AbstractFunction const& function) = 0;
		virtual std::string generateToDefault(AbstractFunction const& function) = 0;
	};

	class DefaultConvention : public CallingConvention {
	public:
		~DefaultConvention() override;

		std::string generateFromDefault(AbstractFunction const& function) override;
		std::string generateToDefault(AbstractFunction const& function) override;
	};
}