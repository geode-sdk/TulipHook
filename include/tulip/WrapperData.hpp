#pragma once

#include "AbstractFunction.hpp"
#include "HandlerData.hpp"

#include <memory>

namespace tulip::hook {
    class CallingConvention;

    class WrapperMetadata {
    public:
        std::shared_ptr<CallingConvention> m_convention;

        AbstractFunction m_abstract;
    };
}