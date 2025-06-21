#pragma once

#include <vector>
#include <span>

inline std::vector<uint8_t> operator""_bytes(char const* data, size_t size) {
    return {reinterpret_cast<uint8_t const*>(data), reinterpret_cast<uint8_t const*>(data + size)};
}

namespace std {

    inline bool operator==(std::span<uint8_t const> lhs, std::vector<uint8_t> const& rhs) {
        if (lhs.size() != rhs.size()) {
            return false;
        }
        for (size_t i = 0; i < lhs.size(); ++i) {
            if (lhs[i] != rhs[i]) {
                return false;
            }
        }
        return true;
    }

}