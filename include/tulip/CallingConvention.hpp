#pragma once

#include <string>

namespace tulip::hook {
	class AbstractFunction;

	class CallingConvention {
	public:
		virtual ~CallingConvention() = 0;

		/**
		 * Generate the code for converting the function args from the
		 * custom convention to cdecl
		 */
		virtual std::string generateIntoDefault(AbstractFunction const& function) = 0;
		/**
		 * Generate the code for cleaning up the stack after our cdecl
		 * detour is done (since cdecl is caller-cleanup)
		 */
		virtual std::string generateDefaultCleanup(AbstractFunction const& function) = 0;

		/**
		 * Generate the code for converting the function args from cdecl
		 * to the custom convention
		 */
		virtual std::string generateIntoOriginal(AbstractFunction const& function) = 0;
		/**
		 * Generate the code for cleaning up the stack after the custom
		 * convention is done (since cdecl is caller-cleanup)
		 */
		virtual std::string generateOriginalCleanup(AbstractFunction const& function) = 0;
	};
}
