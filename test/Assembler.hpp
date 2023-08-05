#pragma once

#include <vector>

inline std::vector<uint8_t> operator""_bytes(char const* data, size_t size) {
	return {reinterpret_cast<uint8_t const*>(data), reinterpret_cast<uint8_t const*>(data + size)};
}