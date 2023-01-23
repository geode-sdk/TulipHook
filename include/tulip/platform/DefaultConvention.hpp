#pragma once

#include "../CallingConvention.hpp"
#include <memory>
#include <string>

namespace tulip::hook {
	class AbstractFunction;

	class TULIP_HOOK_DLL DefaultConvention : public CallingConvention {
	public:
		~DefaultConvention() override;

		std::string generateDefaultCleanup(AbstractFunction const& function) override;
		std::string generateIntoDefault(AbstractFunction const& function) override;
		std::string generateIntoOriginal(AbstractFunction const& function) override;
		std::string generateOriginalCleanup(AbstractFunction const& function) override;

		static std::shared_ptr<DefaultConvention> create();
	};
}
