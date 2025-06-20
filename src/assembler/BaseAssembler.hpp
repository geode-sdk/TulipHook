#pragma once

#include <stdint.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <tulip/Platform.hpp>
#include <span>

namespace tulip::hook {

	struct AssemblerLabelUpdates {
		int64_t m_address;
		std::string m_name;
		uint8_t m_size;
		uint8_t m_offset;
	};

	class TULIP_HOOK_DLL BaseAssembler {
	public:
		int64_t m_baseAddress;
		std::vector<uint8_t> m_buffer;
		std::unordered_map<std::string, int64_t> m_labels;
		std::vector<AssemblerLabelUpdates> m_labelUpdates;
		std::vector<AssemblerLabelUpdates> m_absoluteLabelUpdates;

		BaseAssembler(int64_t baseAddress);
		BaseAssembler(BaseAssembler const&) = delete;
		BaseAssembler(BaseAssembler&&) = delete;
		virtual ~BaseAssembler();

		int64_t currentAddress() const;
		std::span<uint8_t const> buffer() const;

		uint8_t read8(int64_t address) const;
		uint16_t read16(int64_t address) const;
		uint32_t read32(int64_t address) const;
		uint64_t read64(int64_t address) const;

		void write8(uint8_t value);
		void write16(uint16_t value);
		void write32(uint32_t value);
		void write64(uint64_t value);

		void writeBuffer(std::span<uint8_t> span);

		void rewrite8(int64_t address, uint8_t value);
		void rewrite16(int64_t address, uint16_t value);
		void rewrite32(int64_t address, uint32_t value);
		void rewrite64(int64_t address, uint64_t value);

		void label(std::string const& name);

		int64_t getLabel(std::string const& name) const;

		virtual void updateLabels();
	};
}