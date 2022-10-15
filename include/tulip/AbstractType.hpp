#pragma once

#include <cstdint>
#include <string>
#include <type_traits>

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

		template <class Type>
		static AbstractType from() {
			AbstractType type;
			type.m_size = sizeof(Type);
			if constexpr(std::is_floating_point_v<Type>) {
				type.m_type = AbstractTypeType::FloatingPoint;
			}
			else if constexpr(!std::is_class_v<Type>) {
				type.m_type = AbstractTypeType::Primitive;
			}
			else {
				type.m_type = AbstractTypeType::Other;
			}
			

			return type;
		}
	};
}