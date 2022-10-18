#pragma once

#include <memory>

#include <capstone/capstone.h>
#include <keystone/keystone.h>

namespace tulip::hook {
	class Target {
	protected:
		ks_engine* m_keystone = nullptr;
		csh m_capstone = 0;

		void* m_allocatedPage = nullptr;
		size_t m_currentOffset = 0;
		size_t m_remainingOffset = 0;

	public:
		void* allocateArea(size_t size);

		void writeMemory(void* destination, void* source, size_t size);

		virtual ks_engine* openKeystone() = 0;
		void closeKeystone(ks_engine* engine);
		ks_engine* getKeystone();

		virtual csh openCapstone() = 0;
		void closeCapstone(csh engine);
		csh getCapstone();

		virtual void allocatePage() = 0;
		virtual uint32_t getProtection(void* address) = 0;
		virtual void protectMemory(void* address, size_t size, uint32_t protection) = 0;
		virtual void rawWriteMemory(void* destination, void* source, size_t size) = 0;
		virtual uint32_t getMaxProtection() = 0;
	};
};