#pragma once

#include <memory>

#include "AbstractFunction.hpp"

namespace tulip::hook {
	class CallingConvention;

	using HandlerHandle = size_t;

	class HandlerMetadata {
	public:
		std::shared_ptr<CallingConvention> m_convention;

		AbstractFunction m_abstract;
	};
}