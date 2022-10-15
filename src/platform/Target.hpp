#pragma once

#include <memory>

#include <capstone/capstone.h>
#include <keystone/keystone.h>

namespace tulip::hook {
	class Target {
	protected:
		class TargetImpl;
		std::unique_ptr<TargetImpl> m_impl;

		Target();

	public:
		static Target& get();

		void* allocateArea(size_t size);

		void writeMemory(void* destination, void* source, size_t size);

		ks_engine* openKeystone();
		void closeKeystone(ks_engine* engine);
		ks_engine* getKeystone();

		csh openCapstone();
		void closeCapstone(csh engine);
		csh getCapstone();
	};
};