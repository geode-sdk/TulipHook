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

		WrapperMetadata() = default;
		WrapperMetadata(HandlerMetadata const& handlerMetadata)
			: m_convention(handlerMetadata.m_convention),
			  m_abstract(handlerMetadata.m_abstract) {}
	};
}