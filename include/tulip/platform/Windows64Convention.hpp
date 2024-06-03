#pragma once

#include "../Platform.hpp"

#if defined(TULIP_HOOK_WINDOWS) && defined(TULIP_HOOK_X64)

#include "DefaultConvention.hpp"

#include <memory>
#include <string>

namespace tulip::hook {
	class AbstractFunction;

	class TULIP_HOOK_DLL Windows64Convention : public DefaultConvention {
	public:
		~Windows64Convention() override;

		void generateDefaultCleanup(BaseAssembler& a, AbstractFunction const& function) override;
		void generateIntoDefault(BaseAssembler& a, AbstractFunction const& function) override;

		static std::shared_ptr<Windows64Convention> create();
	};

	class TULIP_HOOK_DLL ThiscallConvention : public Windows64Convention {
	public:
		~ThiscallConvention() override;

		void generateIntoDefault(BaseAssembler& a, AbstractFunction const& function) override;
		void generateIntoOriginal(BaseAssembler& a, AbstractFunction const& function) override;
		void generateOriginalCleanup(BaseAssembler& a, AbstractFunction const& function) override;
		bool needsWrapper(AbstractFunction const& function) const override;

		static std::shared_ptr<ThiscallConvention> create();
	};
}

#endif
