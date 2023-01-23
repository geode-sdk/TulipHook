#pragma once

#include "../CallingConvention.hpp"
#include <memory>
#include <string>

namespace tulip::hook {
	class AbstractFunction;

	class TULIP_HOOK_DLL CdeclConvention : public CallingConvention {
	public:
		~CdeclConvention() override;

		std::string generateDefaultCleanup(AbstractFunction const& function) override;
		std::string generateIntoDefault(AbstractFunction const& function) override;
		std::string generateIntoOriginal(AbstractFunction const& function) override;
		std::string generateOriginalCleanup(AbstractFunction const& function) override;

		static std::shared_ptr<CdeclConvention> create();
	};

	class TULIP_HOOK_DLL ThiscallConvention : public CallingConvention {
	public:
		~ThiscallConvention() override;

		std::string generateDefaultCleanup(AbstractFunction const& function) override;
		std::string generateIntoDefault(AbstractFunction const& function) override;
		std::string generateIntoOriginal(AbstractFunction const& function) override;
		std::string generateOriginalCleanup(AbstractFunction const& function) override;

		static std::shared_ptr<ThiscallConvention> create();
	};

	class TULIP_HOOK_DLL FastcallConvention : public CallingConvention {
	public:
		~FastcallConvention() override;

		std::string generateDefaultCleanup(AbstractFunction const& function) override;
		std::string generateIntoDefault(AbstractFunction const& function) override;
		std::string generateIntoOriginal(AbstractFunction const& function) override;
		std::string generateOriginalCleanup(AbstractFunction const& function) override;

		static std::shared_ptr<FastcallConvention> create();
	};

	class TULIP_HOOK_DLL OptcallConvention : public CallingConvention {
	public:
		~OptcallConvention() override;

		std::string generateDefaultCleanup(AbstractFunction const& function) override;
		std::string generateIntoDefault(AbstractFunction const& function) override;
		std::string generateIntoOriginal(AbstractFunction const& function) override;
		std::string generateOriginalCleanup(AbstractFunction const& function) override;

		static std::shared_ptr<OptcallConvention> create();
	};

	class TULIP_HOOK_DLL MembercallConvention : public CallingConvention {
	public:
		~MembercallConvention() override;

		std::string generateDefaultCleanup(AbstractFunction const& function) override;
		std::string generateIntoDefault(AbstractFunction const& function) override;
		std::string generateIntoOriginal(AbstractFunction const& function) override;
		std::string generateOriginalCleanup(AbstractFunction const& function) override;

		static std::shared_ptr<MembercallConvention> create();
	};
}
