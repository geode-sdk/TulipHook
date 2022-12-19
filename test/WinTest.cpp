#include <tulip/TulipHook.hpp>
#include <iostream>

#define NO_INLINE __declspec(noinline)

struct FooBar {
	int number;

	NO_INLINE bool __thiscall targetFunc(int stack, int stack2) {
		std::cout << "I am FooBar::targetFunc\n";
		std::cout << "  I live at " << this << " avenue\n";
		std::cout << "  My number is " << this->number << "\n";
		std::cout << "  My stack is " << stack << " and " << stack2 << "\n";
		return true;
	}
};

NO_INLINE bool __cdecl targetFuncHook(FooBar* self, int stack, int stack2) {
	std::cout << "I am targetFuncHook" << std::endl;
	std::cout << "  I robbed " << self << " avenue" << std::endl;
	std::cout << "  I stole the stack of " << stack << " and " << stack2 << std::endl;
	self->targetFunc(stack, stack2);
	std::cout << "Setting number to 69" << std::endl;
	self->number = 69;
	auto ret = self->targetFunc(420, stack2);
	std::cout << "The burglared one returned: " << ret << std::endl;
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

	std::cout << "## __thiscall -> __cdecl ##\n";
	std::cout << metadata.m_convention->generateIntoDefault(metadata.m_abstract) << "\n";

	std::cout << "## __cdecl stack fix ##\n";
	std::cout << metadata.m_convention->generateDefaultCleanup(metadata.m_abstract) << "\n";

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
	auto value = bar->targetFunc(5, 7);

	std::cout << "targetFunc returned " << value << std::endl;

	return 0;
}