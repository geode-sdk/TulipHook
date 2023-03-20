#include <AbstractFunction.hpp>

using namespace tulip::hook;

void AbstractFunction::addType(AbstractType const& type) {
	m_parameters.push_back(std::move(type));
}