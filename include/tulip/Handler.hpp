#pragma once

#include <memory>

namespace tulip::hook {
	class CallingConvention;

	class HandlerHandle {
	public:
		void* m_address;
	};

	class HandlerMetadata {
	public:
		std::unique_ptr<CallingConvention> m_convention;
	};
}