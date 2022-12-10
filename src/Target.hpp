#pragma once

#include <Result.hpp>
#include <capstone/capstone.h>
#include <keystone/keystone.h>
#include <memory>

namespace tulip::hook {
	class Target {
	protected:
		ks_engine* m_keystone = nullptr;
		csh m_capstone = 0;

		void* m_allocatedPage = nullptr;
		size_t m_currentOffset = 0;
		size_t m_remainingOffset = 0;

	public:
		Result<void*> allocateArea(size_t size);

		Result<> writeMemory(void* destination, void* source, size_t size);

		virtual Result<ks_engine*> openKeystone() = 0;
		void closeKeystone();
		ks_engine* getKeystone();

		virtual Result<csh> openCapstone() = 0;
		void closeCapstone();
		csh getCapstone();

		virtual Result<> allocatePage() = 0;
		virtual Result<uint32_t> getProtection(void* address) = 0;
		virtual Result<> protectMemory(void* address, size_t size, uint32_t protection) = 0;
		virtual Result<> rawWriteMemory(void* destination, void* source, size_t size) = 0;
		virtual uint32_t getMaxProtection() = 0;
	};
};
