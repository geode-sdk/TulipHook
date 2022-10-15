#pragma once

#include "../Platform.hpp"
#if defined(TULIP_HOOK_WINDOWS)

#include <string>

#include "../CallingConvention.hpp"

namespace tulip::hook {
	class AbstractFunction;

	class CdeclConvention : public CallingConvention {
	public:
		~CdeclConvention() override;

		std::string generateFromDefault(AbstractFunction const& function) override;
		std::string generateToDefault(AbstractFunction const& function) override;
	};

	class ThiscallConvention : public CallingConvention {
	public:
		~ThiscallConvention() override;

		std::string generateFromDefault(AbstractFunction const& function) override;
		std::string generateToDefault(AbstractFunction const& function) override;
	};

	class OptcallConvention : public CallingConvention {
	public:
		~OptcallConvention() override;

		std::string generateFromDefault(AbstractFunction const& function) override;
		std::string generateToDefault(AbstractFunction const& function) override;
	};

	class MembercallConvention : public CallingConvention {
	public:
		~MembercallConvention() override;

		std::string generateFromDefault(AbstractFunction const& function) override;
		std::string generateToDefault(AbstractFunction const& function) override;
	};
}

#endif