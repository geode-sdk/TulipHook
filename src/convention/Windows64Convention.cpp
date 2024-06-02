#include <Platform.hpp>

#if defined(TULIP_HOOK_WINDOWS) && defined(TULIP_HOOK_X64)

#include <AbstractFunction.hpp>
#include <platform/Windows64Convention.hpp>
#include "../assembler/X64Assembler.hpp"

using namespace tulip::hook;

ThiscallConvention::~ThiscallConvention() {}

void ThiscallConvention::generateDefaultCleanup(BaseAssembler& a, AbstractFunction const& function) {
    static_cast<X64Assembler&>(a).ret();
}

// Member functions deal with struct return differently, since in the windows x64 convention
// a struct return is as a hidden first parameter, member functions end up considering the first parameter
// the one after the `this`, whereas static functions do not.
//
// So where a static function would behave like this:
// SomeStruct* func(SomeStruct* ret_ptr, Class* self, int a, int b);
// a member function would behave like this:
// SomeStruct* Class::method(Class* this, SomeStruct* ret_ptr, int a, int b);
// so to undo this we just swap the first two parameters (RCX and RDX).

void ThiscallConvention::generateIntoDefault(BaseAssembler& a_, AbstractFunction const& function) {
    if (function.m_return.m_kind == AbstractTypeKind::Other) {
        auto& a = static_cast<X64Assembler&>(a_);
        using enum X64Register;
        a.xchg(RCX, RDX);
    }
}

void ThiscallConvention::generateIntoOriginal(BaseAssembler& a_, AbstractFunction const& function) {
    if (function.m_return.m_kind == AbstractTypeKind::Other) {
        auto& a = static_cast<X64Assembler&>(a_);
        using enum X64Register;
        a.xchg(RCX, RDX);
    }
}

void ThiscallConvention::generateOriginalCleanup(BaseAssembler& a, AbstractFunction const& function) {
    static_cast<X64Assembler&>(a).ret();
}

bool ThiscallConvention::needsWrapper(AbstractFunction const& function) const {
	return function.m_return.m_kind == AbstractTypeKind::Other;
}

std::shared_ptr<ThiscallConvention> ThiscallConvention::create() {
	return std::make_shared<ThiscallConvention>();
}

#endif