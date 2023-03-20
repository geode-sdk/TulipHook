#pragma once

#include "AbstractType.hpp"
#include "Platform.hpp"

#include <string>
#include <type_traits>
#include <vector>

namespace tulip::hook {
	class TULIP_HOOK_DLL AbstractFunction {
		template <class FunctionType>
		struct Generator {
			static AbstractFunction generate() {
				return AbstractFunction();
			}
		};

		template <class Return, class... Parameters>
		struct Generator<Return(Parameters...)> {
			static AbstractFunction generate() {
				AbstractFunction func;
				func.m_return = AbstractType::from<Return>();
				(func.addType(AbstractType::from<Parameters>()), ...);

				return func;
			}
		};

	public:
		void addType(AbstractType const& type);

		AbstractType m_return;
		std::vector<AbstractType> m_parameters;

		template <class FunctionType>
		static AbstractFunction from() {
			return Generator<FunctionType>::generate();
		}

		template <class Return, class... Parameters>
		static AbstractFunction from(Return (*)(Parameters...)) {
			AbstractFunction func;
			func.m_return = AbstractType::from<Return>();
			(func.addType(AbstractType::from<Parameters>()), ...);

			return func;
		}
	};
}
