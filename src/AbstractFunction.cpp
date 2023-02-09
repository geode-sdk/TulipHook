#include <AbstractFunction.hpp>

using namespace tulip::hook;

AbstractFunction::~AbstractFunction() {}

AbstractFunction::AbstractFunction() :
	m_return(),
	m_parameters() {}

AbstractFunction::AbstractFunction(AbstractFunction const& other) :
	m_return(other.m_return),
	m_parameters(other.m_parameters) {}

AbstractFunction::AbstractFunction(AbstractFunction&& other) :
	m_return(std::move(other.m_return)),
	m_parameters(std::move(other.m_parameters)) {}

AbstractFunction& AbstractFunction::operator=(AbstractFunction const& other) {
	m_return = other.m_return;
	m_parameters = other.m_parameters;
	return *this;
}

AbstractFunction& AbstractFunction::operator=(AbstractFunction&& other) {
	m_return = std::move(other.m_return);
	m_parameters = std::move(other.m_parameters);
	return *this;
}

void AbstractFunction::addType(AbstractType const& type) {
	m_parameters.push_back(std::move(type));
}