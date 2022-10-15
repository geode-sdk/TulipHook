#pragma once

#include <cstdint>
#include <string>

namespace tulip::hook {
	enum class AbstractTypeType : uint8_t {
		Primitive,
		FloatingPoint,
		Other,
	};

	class AbstractType {
	public:
		std::string m_name;
		size_t m_size;
		AbstractTypeType m_type;
	};
}