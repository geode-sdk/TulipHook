#pragma once

#include <Platform.hpp>

#ifdef TULIP_HOOK_WINDOWS

#include "../CallingConvention.hpp"

#include <memory>
#include <string>

namespace tulip::hook {
	class AbstractFunction;

	class TULIP_HOOK_DLL CdeclConvention : public CallingConvention {
	public:
		~CdeclConvention() override;

		void generateDefaultCleanup(BaseAssembler& a, AbstractFunction const& function) override;
		void generateIntoDefault(BaseAssembler& a, AbstractFunction const& function) override;
		void generateIntoOriginal(BaseAssembler& a, AbstractFunction const& function) override;
		void generateOriginalCleanup(BaseAssembler& a, AbstractFunction const& function) override;

		static std::shared_ptr<CdeclConvention> create();
	};

	class TULIP_HOOK_DLL ThiscallConvention : public CallingConvention {
	public:
		~ThiscallConvention() override;

		void generateDefaultCleanup(BaseAssembler& a, AbstractFunction const& function) override;
		void generateIntoDefault(BaseAssembler& a, AbstractFunction const& function) override;
		void generateIntoOriginal(BaseAssembler& a, AbstractFunction const& function) override;
		void generateOriginalCleanup(BaseAssembler& a, AbstractFunction const& function) override;

		static std::shared_ptr<ThiscallConvention> create();
	};

	class TULIP_HOOK_DLL FastcallConvention : public CallingConvention {
	public:
		~FastcallConvention() override;

		void generateDefaultCleanup(BaseAssembler& a, AbstractFunction const& function) override;
		void generateIntoDefault(BaseAssembler& a, AbstractFunction const& function) override;
		void generateIntoOriginal(BaseAssembler& a, AbstractFunction const& function) override;
		void generateOriginalCleanup(BaseAssembler& a, AbstractFunction const& function) override;

		static std::shared_ptr<FastcallConvention> create();
	};

	class TULIP_HOOK_DLL OptcallConvention : public CallingConvention {
	public:
		~OptcallConvention() override;

		void generateDefaultCleanup(BaseAssembler& a, AbstractFunction const& function) override;
		void generateIntoDefault(BaseAssembler& a, AbstractFunction const& function) override;
		void generateIntoOriginal(BaseAssembler& a, AbstractFunction const& function) override;
		void generateOriginalCleanup(BaseAssembler& a, AbstractFunction const& function) override;

		static std::shared_ptr<OptcallConvention> create();
	};

	class TULIP_HOOK_DLL MembercallConvention : public CallingConvention {
	public:
		~MembercallConvention() override;

		void generateDefaultCleanup(BaseAssembler& a, AbstractFunction const& function) override;
		void generateIntoDefault(BaseAssembler& a, AbstractFunction const& function) override;
		void generateIntoOriginal(BaseAssembler& a, AbstractFunction const& function) override;
		void generateOriginalCleanup(BaseAssembler& a, AbstractFunction const& function) override;

		static std::shared_ptr<MembercallConvention> create();
	};

	class TULIP_HOOK_DLL StdcallConvention : public CallingConvention {
	public:
		~StdcallConvention() override;

		void generateDefaultCleanup(BaseAssembler& a, AbstractFunction const& function) override;
		void generateIntoDefault(BaseAssembler& a, AbstractFunction const& function) override;
		void generateIntoOriginal(BaseAssembler& a, AbstractFunction const& function) override;
		void generateOriginalCleanup(BaseAssembler& a, AbstractFunction const& function) override;

		static std::shared_ptr<StdcallConvention> create();
	};
}

#endif
