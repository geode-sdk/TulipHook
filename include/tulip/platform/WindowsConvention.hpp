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
		std::string generateBackFromDefault(AbstractFunction const& function) override;
		std::string generateBackToDefault(AbstractFunction const& function, size_t stackOffset) override;
	};

	class ThiscallConvention : public CallingConvention {
	public:
		~ThiscallConvention() override;

		std::string generateFromDefault(AbstractFunction const& function) override;
		std::string generateToDefault(AbstractFunction const& function) override;
		std::string generateBackFromDefault(AbstractFunction const& function) override;
		std::string generateBackToDefault(AbstractFunction const& function, size_t stackOffset) override;
	};

	class FastcallConvention : public CallingConvention {
	public:
		~FastcallConvention() override;

		std::string generateFromDefault(AbstractFunction const& function) override;
		std::string generateToDefault(AbstractFunction const& function) override;
		std::string generateBackFromDefault(AbstractFunction const& function) override;
		std::string generateBackToDefault(AbstractFunction const& function, size_t stackOffset) override;
	};

	class OptcallConvention : public CallingConvention {
	public:
		~OptcallConvention() override;

		std::string generateFromDefault(AbstractFunction const& function) override;
		std::string generateToDefault(AbstractFunction const& function) override;
		std::string generateBackFromDefault(AbstractFunction const& function) override;
		std::string generateBackToDefault(AbstractFunction const& function, size_t stackOffset) override;
	};

	class MembercallConvention : public CallingConvention {
	public:
		~MembercallConvention() override;

		std::string generateFromDefault(AbstractFunction const& function) override;
		std::string generateToDefault(AbstractFunction const& function) override;
		std::string generateBackFromDefault(AbstractFunction const& function) override;
		std::string generateBackToDefault(AbstractFunction const& function, size_t stackOffset) override;
	};

	using PlatformConvention = CdeclConvention;
}

#endif
