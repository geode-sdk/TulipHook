#pragma once

#include "../Platform.hpp"

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

    class TULIP_HOOK_DLL Thiscall64Convention : public Windows64Convention {
    public:
        ~Thiscall64Convention() override;

        void generateIntoDefault(BaseAssembler& a, AbstractFunction const& function) override;
        void generateIntoOriginal(BaseAssembler& a, AbstractFunction const& function) override;
        void generateOriginalCleanup(BaseAssembler& a, AbstractFunction const& function) override;
        bool needsWrapper(AbstractFunction const& function) const override;

        static std::shared_ptr<Thiscall64Convention> create();
    };
}

