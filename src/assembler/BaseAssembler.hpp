#pragma once

#include <stdint.h>
#include <string>
#include <unordered_map>
#include <vector>

namespace tulip::hook {

	struct AssemblerLabelUpdates {
		uint64_t m_address;
		std::string m_name;
		uint8_t m_size;
	};

	class BaseAssembler {
	public:
		uint64_t m_baseAddress;
		std::vector<uint8_t> m_buffer;
		std::unordered_map<std::string, uint64_t> m_labels;
		std::vector<AssemblerLabelUpdates> m_labelUpdates;

		BaseAssembler(uint64_t baseAddress);
		BaseAssembler(BaseAssembler const&) = delete;
		BaseAssembler(BaseAssembler&&) = delete;
		~BaseAssembler();

		uint64_t currentAddress() const;

		void write8(uint8_t value);
		void write16(uint16_t value);
		void write32(uint32_t value);
		void write64(uint64_t value);

		void rewrite8(uint64_t address, uint8_t value);
		void rewrite16(uint64_t address, uint16_t value);
		void rewrite32(uint64_t address, uint32_t value);
		void rewrite64(uint64_t address, uint64_t value);

		void label(std::string const& name);

		virtual void updateLabels();
	};
}