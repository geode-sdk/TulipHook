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

	static void keystoneCloseFun() {
		PlatformTarget::get().closeKeystone();
	};

	using KSHolder = RAIIHolder<ks_engine*, &keystoneCloseFun>;

	static void capstoneCloseFun() {
		PlatformTarget::get().closeCapstone();
	};

	using CSHolder = RAIIHolder<csh, &capstoneCloseFun>;
}