#include "../assembler/BaseAssembler.hpp"

#include <Platform.hpp>
#include <platform/DefaultConvention.hpp>

using namespace tulip::hook;

DefaultConvention::~DefaultConvention() {}

void DefaultConvention::generateDefaultCleanup(BaseAssembler& a, AbstractFunction const& function) {}

void DefaultConvention::generateIntoDefault(BaseAssembler& a, AbstractFunction const& function) {}

void DefaultConvention::generateIntoOriginal(BaseAssembler& a, AbstractFunction const& function) {}

void DefaultConvention::generateOriginalCleanup(BaseAssembler& a, AbstractFunction const& function) {}

bool DefaultConvention::needsWrapper(AbstractFunction const& function) const {
	return false;
}

std::shared_ptr<DefaultConvention> DefaultConvention::create() {
	return std::make_shared<DefaultConvention>();
}
