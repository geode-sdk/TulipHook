#pragma once

#include "../CallingConvention.hpp"

#include <string>

namespace tulip::hook {
	class AbstractFunction;

	class CdeclConvention : public CallingConvention {
	public:
		~CdeclConvention() override;

		std::string generateDefaultCleanup(AbstractFunction const& function) override;
		std::string generateIntoDefault(AbstractFunction const& function) override;
		std::string generateIntoOriginal(AbstractFunction const& function) override;
		std::string generateOriginalCleanup(AbstractFunction const& function) override;
	};

	class ThiscallConvention : public CallingConvention {
	public:
		~ThiscallConvention() override;

		std::string generateDefaultCleanup(AbstractFunction const& function) override;
		std::string generateIntoDefault(AbstractFunction const& function) override;
		std::string generateIntoOriginal(AbstractFunction const& function) override;
		std::string generateOriginalCleanup(AbstractFunction const& function) override;
	};

	class FastcallConvention : public CallingConvention {
	public:
		~FastcallConvention() override;

		std::string generateDefaultCleanup(AbstractFunction const& function) override;
		std::string generateIntoDefault(AbstractFunction const& function) override;
		std::string generateIntoOriginal(AbstractFunction const& function) override;
		std::string generateOriginalCleanup(AbstractFunction const& function) override;
	};

	class OptcallConvention : public CallingConvention {
	public:
		~OptcallConvention() override;

		std::string generateDefaultCleanup(AbstractFunction const& function) override;
		std::string generateIntoDefault(AbstractFunction const& function) override;
		std::string generateIntoOriginal(AbstractFunction const& function) override;
		std::string generateOriginalCleanup(AbstractFunction const& function) override;
	};

	class MembercallConvention : public CallingConvention {
	public:
		~MembercallConvention() override;

		std::string generateDefaultCleanup(AbstractFunction const& function) override;
		std::string generateIntoDefault(AbstractFunction const& function) override;
		std::string generateIntoOriginal(AbstractFunction const& function) override;
		std::string generateOriginalCleanup(AbstractFunction const& function) override;
	};
}
