#pragma once

#include <FunctionData.hpp>
#include <HandlerData.hpp>
#include <Geode/Result.hpp>
#include <WrapperData.hpp>
#include <memory>

namespace tulip::hook {

	class BaseGenerator {
	public:
		BaseGenerator() = default;

		virtual ~BaseGenerator() = default;

		struct RelocateReturn {
			std::vector<uint8_t> bytes;
			size_t offset; // can be different than size
		};

		virtual std::vector<uint8_t> handlerBytes(int64_t original, int64_t handler, void* content, HandlerMetadata const& metadata);
		virtual std::vector<uint8_t> intervenerBytes(int64_t original, int64_t handler, size_t size);
		virtual geode::Result<RelocateReturn> relocatedBytes(int64_t original, int64_t relocated, size_t size);
		virtual std::vector<uint8_t> wrapperBytes(int64_t original, int64_t wrapper, WrapperMetadata const& metadata);
		virtual std::vector<uint8_t> runtimeInfoBytes(int64_t function, size_t size, int64_t push, int64_t alloc);
		virtual std::vector<uint8_t> commonHandlerBytes(int64_t handler, ptrdiff_t spaceOffset);
		virtual std::vector<uint8_t> commonIntervenerBytes(int64_t original, int64_t handler, size_t unique, ptrdiff_t relocOffset);
	};
}
