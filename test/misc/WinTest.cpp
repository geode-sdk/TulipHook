#include "tulip/TulipHook.hpp"

#include <iostream>

#define NO_INLINE __declspec(noinline)

struct Dummy {
    int x, y, z, d;
    ~Dummy() {}
};

struct FooBar {
    int number;

    NO_INLINE Dummy targetFunc(int stack, int stack2) {
        std::cout << "I am FooBar::targetFunc\n";
        std::cout << "  this: " << this << "\n";
        std::cout << "  this->number: " << this->number << "\n";
        std::cout << "  My stack is " << stack << " and " << stack2 << "\n";
        return {.x = 3};
    }
};

NO_INLINE Dummy targetFuncHook(FooBar* self, int stack, int stack2) {
    std::cout << "I am targetFuncHook" << std::endl;
    std::cout << "  this: " << self << std::endl;
    std::cout << "  this->number: " << self->number << "\n";
    std::cout << "  My stack " << stack << " and " << stack2 << std::endl;
    return self->targetFunc(stack, stack2);
}

int main() {
    auto poo = &FooBar::targetFunc;
    void* address = reinterpret_cast<void*&>(poo);

    std::cout << "address of FooBar::targetFunc is " << address << std::endl;

    auto metadata = tulip::hook::HandlerMetadata {
        .m_convention = std::make_shared<tulip::hook::ThiscallConvention>(),
        .m_abstract = tulip::hook::AbstractFunction::from(&targetFuncHook)
    };

    auto handleResult = tulip::hook::createHandler(address, metadata);
    if (!handleResult) {
        std::cout << "creating the handler failed" << std::endl;
        return 1;
    }
    auto handle = handleResult.unwrap();

    auto h_metadata = tulip::hook::HookMetadata {
        .m_priority = 2
    };

    tulip::hook::createHook(handle, (void*)&targetFuncHook, h_metadata);

    std::cout << "hook created!" << std::endl;

    auto bar = new FooBar;
    std::cout << "bar is " << bar << std::endl;
    bar->number = 23;
    auto value = bar->targetFunc(5, 7);

    std::cout << "targetFunc returned " << value.x << std::endl;

    return 0;
}
