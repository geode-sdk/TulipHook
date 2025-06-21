#pragma once

#include <string>

namespace tulip::hook {
    class BaseAssembler;
    class AbstractFunction;

    class CallingConvention {
    public:
        virtual ~CallingConvention() = 0;

        /**
         * Generate the code for converting the function args from the
         * custom convention to cdecl
         */
        virtual void generateIntoDefault(BaseAssembler& a, AbstractFunction const& function) = 0;
        /**
         * Generate the code for cleaning up the stack after our cdecl
         * detour is done (since cdecl is caller-cleanup)
         */
        virtual void generateDefaultCleanup(BaseAssembler& a, AbstractFunction const& function) = 0;

        /**
         * Generate the code for converting the function args from cdecl
         * to the custom convention
         */
        virtual void generateIntoOriginal(BaseAssembler& a, AbstractFunction const& function) = 0;
        /**
         * Generate the code for cleaning up the stack after the custom
         * convention is done (since cdecl is caller-cleanup)
         */
        virtual void generateOriginalCleanup(BaseAssembler& a, AbstractFunction const& function) = 0;
        /**
         * Check if the function needs a wrapper generated
         */
        virtual bool needsWrapper(AbstractFunction const& function) const = 0;
    };
}
