#pragma once

#include "../Platform.hpp"

#include "../CallingConvention.hpp"

#include <memory>
#include <string>

namespace tulip::hook {
    class AbstractFunction;

    class TULIP_HOOK_DLL AAPCS64Convention : public CallingConvention {
    public:
        ~AAPCS64Convention() override;

        void generateDefaultCleanup(BaseAssembler& a, AbstractFunction const& function) override;
        void generateIntoDefault(BaseAssembler& a, AbstractFunction const& function) override;
        void generateIntoOriginal(BaseAssembler& a, AbstractFunction const& function) override;
        void generateOriginalCleanup(BaseAssembler& a, AbstractFunction const& function) override;
        bool needsWrapper(AbstractFunction const& function) const override;

        static std::shared_ptr<AAPCS64Convention> create();
    };
}
