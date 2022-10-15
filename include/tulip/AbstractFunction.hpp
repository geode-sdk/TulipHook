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
	};
}