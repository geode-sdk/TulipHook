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
            if constexpr (std::is_same_v<Type, void>) {
                type.m_kind = AbstractTypeKind::Primitive;
                type.m_size = 1;
            }
            else if constexpr (std::is_floating_point_v<Type>) {
                type.m_kind = AbstractTypeKind::FloatingPoint;
                type.m_size = sizeof(Type);
            }
            else if constexpr (!std::is_class_v<Type>) {
                type.m_kind = AbstractTypeKind::Primitive;
                type.m_size = std::is_reference_v<Type> ? sizeof(void*) : sizeof(Type);
            }
            else {
                type.m_kind = AbstractTypeKind::Other;
                type.m_size = sizeof(Type);
            }
            return type;
        }
    };
}
