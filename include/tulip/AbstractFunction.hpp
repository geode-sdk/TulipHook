#pragma once

#include <vector>
#include <string>

#include "AbstractType.hpp"

namespace tulip::hook {
	class AbstractFunction {
	public:
		std::string m_name;
		AbstractType m_return;
		std::vector<AbstractType> m_parameters;

		template <class Return, class... Parameters>
		static AbstractFunction from() {
			AbstractFunction func;
			func.m_return = AbstractType::from<Return>();
			(func.m_parameters.push_back(AbstractType::from<Parameters>()), ...);

			return func;
		}
	};
}