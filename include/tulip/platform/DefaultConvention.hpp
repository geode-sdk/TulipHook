#pragma once

#include "../CallingConvention.hpp"

#include <memory>
#include <string>

namespace tulip::hook {
	class AbstractFunction;

	class TULIP_HOOK_DLL DefaultConvention : public CallingConvention {
	public:
		~DefaultConvention() override;

		void generateDefaultCleanup(BaseAssembler& a, AbstractFunction const& function) override;
		void generateIntoDefault(BaseAssembler& a, AbstractFunction const& function) override;
		void generateIntoOriginal(BaseAssembler& a, AbstractFunction const& function) override;
		void generateOriginalCleanup(BaseAssembler& a, AbstractFunction const& function) override;

		static std::shared_ptr<DefaultConvention> create();
	};
}
