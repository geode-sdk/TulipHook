#pragma once

#include <cstdint>
#include <string>
#include <type_traits>

namespace tulip::hook {
	enum class AbstractTypeKind : uint8_t {
		Primitive,
		FloatingPoint,
		Other,
	};

	class AbstractType {
	public:
		size_t m_size;
		AbstractTypeKind m_kind;

		template <class Type>
		static AbstractType from() {
			AbstractType type;
			type.m_size = sizeof(Type);
			if constexpr(std::is_floating_point_v<Type>) {
				type.m_kind = AbstractTypeKind::FloatingPoint;
			}
			else if constexpr(!std::is_class_v<Type>) {
				type.m_kind = AbstractTypeKind::Primitive;
			}
			else {
				type.m_kind = AbstractTypeKind::Other;
			}
			return type;
		}
	};
}