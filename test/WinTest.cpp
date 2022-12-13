#include <tulip/TulipHook.hpp>
#include <iostream>

#define NO_INLINE __declspec(noinline)

struct FooBar {
	int number;

	NO_INLINE bool __thiscall targetFunc() {
		std::cout << "I am FooBar::targetFunc and my number is " << this->number << std::endl;
		return true;
	}
};

NO_INLINE bool __cdecl targetFuncHook(FooBar* self) {
	std::cout << "I am targetFuncHook" << std::endl;
	self->targetFunc();
	std::cout << "setting number to 69" << std::endl;
	self->number = 69;
	self->targetFunc();
	return false;
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
	auto handle = *handleResult;

	auto h_metadata = tulip::hook::HookMetadata {
		.m_priority = 2
	};

	tulip::hook::createHook(handle, (void*)&targetFuncHook, h_metadata);

	std::cout << "hook created!" << std::endl;

	auto bar = new FooBar;
	bar->number = 23;
	auto value = bar->targetFunc();

	std::cout << "targetFunc returned " << value << std::endl;

	return 0;
}