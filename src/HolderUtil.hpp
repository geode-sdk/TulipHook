#include "platform/PlatformTarget.hpp"

namespace tulip::hook {
	template <class T, auto Fun>
	struct RAIIHolder {
		T m_engine;

		RAIIHolder(T engine) :
			m_engine(engine) {}

		~RAIIHolder() {
			Fun();
		}

		operator T() {
			return m_engine;
		}
	};

	static void capstoneCloseFun() {
		PlatformTarget::get().closeCapstone();
	};

	using CSHolder = RAIIHolder<csh, &capstoneCloseFun>;
}