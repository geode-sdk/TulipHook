#include <algorithm>
#include <cassert>
#include <iostream>
#include <tulip/TulipHook.hpp>
#include <array>

template <class... Params>
int32_t function(Params... params) {
	std::cout << "function called!\n";
	((std::cout << params << " "), ...);
	std::cout << " \n";

	return 1;
}

template <class... Params>
int32_t hook(Params... params) {
	std::cout << "hook begin!\n";
	auto ret = function(params...);
	std::cout << "hook end!\n";

	return 3;
}

template <class... Params>
int32_t priorityHook(Params... params) {
	std::cout << "priority hook begin!\n";
	auto ret = function(params...);
	std::cout << "priority hook end!\n";

	return ret + 3;
}

using namespace tulip::hook;

using FunctionPtrType = int32_t (*)(
	int, int, int, int, int, int, int, int, int, float, float, float, float, float, float, float, float, float, float
);

HandlerHandle makeHandler() {
	// std::cout << "\nmakeHandler\n";
	HandlerMetadata handlerMetadata;
	handlerMetadata.m_convention = std::make_unique<PlatformConvention>();
	handlerMetadata.m_abstract = AbstractFunction::from<int32_t(
		int, int, int, int, int, int, int, int, int, float, float, float, float, float, float, float, float, float, float
	)>();

	auto handle =
		createHandler(reinterpret_cast<void*>(static_cast<FunctionPtrType>(&function)), std::move(handlerMetadata));

	if (handle.isErr()) {
		std::cout << "unable to create handler: " << handle.unwrapErr() << "\n";
		exit(1);
	}

	// std::cout << "\nmakeHandler end\n";

	return handle.unwrap();
}

void destroyHandler(HandlerHandle const& handle) {
	// std::cout << "\ndestroyHandler\n";
	auto rem = removeHandler(handle);
	if (rem.isErr()) {
		std::cout << "unable to remove handler: " << rem.unwrapErr() << "\n";
		exit(1);
	}

	// std::cout << "\ndestroyHandler end\n";
}

HookHandle makeHook(HandlerHandle const& handle) {
	// std::cout << "\nmakeHook\n";
	HookMetadata metadata;

	auto handle2 = createHook(handle, reinterpret_cast<void*>(static_cast<FunctionPtrType>(&hook)), std::move(metadata));

	// std::cout << "\nmakeHook end\n";

	return handle2;
}

void destroyHook(HandlerHandle const& handle, HookHandle const& handle2) {
	// std::cout << "\ndestroyHook\n";
	removeHook(handle, handle2);

	// std::cout << "\ndestroyHook end\n";
}

HookHandle makePriorityHook(HandlerHandle const& handle) {
	// std::cout << "\nmakePriorityHook\n";
	HookMetadata metadata;
	metadata.m_priority = -100;

	auto handle2 =
		createHook(handle, reinterpret_cast<void*>(static_cast<FunctionPtrType>(&priorityHook)), std::move(metadata));

	// std::cout << "\nmakePriorityHook end\n";

	return handle2;
}

void destroyPriorityHook(HandlerHandle const& handle, HookHandle const& handle2) {
	// std::cout << "\ndestroyPriorityHook\n";
	removeHook(handle, handle2);

	// std::cout << "\ndestroyPriorityHook end\n";
}

struct Big {
	int x;
	int y;
	int z;
};

class TextArea;

using GDString = std::array<char, 0x18>;
using CCPoint = std::array<float, 2>;

TextArea* TextArea_create(GDString stack1, char const* ecx, float xmm1, float xmm2, CCPoint stack2, float xmm3, bool edx) {
	return nullptr;
}

bool TextArea_init(
	TextArea* ecx, GDString stack4, char const* stack1, float xmm2, float xmm3, CCPoint stack5, float stack2, bool stack3
) {
	return true;
}

int cconvTest0(Big stack1, int ecx, float stack2) {
	assert(stack1.x == 1);
	assert(stack1.y == 2);
	assert(stack1.z == 3);
	assert(ecx == 4);
	assert(stack2 == 5.f);
	return 6;
}

int cconvTest1(Big stack1, int ecx, float stack2, int edx, float stack3) {
	assert(stack1.x == 1);
	assert(stack1.y == 2);
	assert(stack1.z == 3);
	assert(ecx == 4);
	assert(stack2 == 5.f);
	assert(edx == 6);
	assert(stack3 == 7.f);
	return 8;
}

Big cconvTest2(Big stack1, float stack2, int edx, float stack3) {
	assert(stack1.x == 1);
	assert(stack1.y == 2);
	assert(stack1.z == 3);
	assert(stack2 == 5.f);
	assert(edx == 6);
	assert(stack3 == 7.f);
	return {8, 9, 10};
}

int callFunction() {
	return function(1, 2, 3, 4, 5, 6, 7, 8, 9, 1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f, 9.0f, 10.0f);
}

int main() {
	// No handler
	assert(callFunction() == 1);

	// Handler, no hooks
	std::cout << "\nHandler, no hooks\n";
	HandlerHandle handlerHandle = makeHandler();
	int a;
	// std::cin >> a;

	assert(callFunction() == 1);

	// std::cin >> a;

	// Single hook (hook -> function)
	std::cout << "\nSingle hook (hook -> function)\n";
	HookHandle hookHandle = makeHook(handlerHandle);
	assert(callFunction() == 3);

	// Priority hook (priorityHook -> hook -> function)
	std::cout << "\nPriority hook (priorityHook -> hook -> function)\n";
	HookHandle priorityHookHandle = makePriorityHook(handlerHandle);
	assert(callFunction() == 6);

	// Remove the hook (priorityHook -> function)
	std::cout << "\nRemove the hook (priorityHook -> function)\n";
	destroyHook(handlerHandle, hookHandle);
	assert(callFunction() == 4);

	// Readd the hook (priorityHook -> hook -> function)
	std::cout << "\nReadd the hook (priorityHook -> hook -> function)\n";
	hookHandle = makeHook(handlerHandle);
	assert(callFunction() == 6);

	// Multiple instances of same function
	std::cout << "\nMultiple instances of same function\n";
	HookHandle mult1 = makePriorityHook(handlerHandle);
	HookHandle mult2 = makePriorityHook(handlerHandle);
	HookHandle mult3 = makePriorityHook(handlerHandle);
	assert(callFunction() == 15);

	// Remove the handler
	std::cout << "\nRemove the handler\n";
	destroyHandler(handlerHandle);
	assert(callFunction() == 1);

	// Recreate the handler
	std::cout << "\nRecreate the handler\n";
	HandlerHandle handlerHandle2 = makeHandler();
	assert(callFunction() == 1);

	// Calling convention asm

	auto conv = std::make_unique<OptcallConvention>();
	auto func0 = AbstractFunction::from(&cconvTest0);
	auto func1 = AbstractFunction::from(&cconvTest1);
	auto func2 = AbstractFunction::from(&cconvTest2);

	auto prettify = +[](std::string str) {
		size_t f;
		while ((f = str.find("; ")) != std::string::npos) {
			str = str.replace(str.begin() + f, str.begin() + f + 2, "\n", 1);
		}
		return str;
	};

	auto optcall = std::make_unique<OptcallConvention>();
	auto textArea_create = AbstractFunction::from(&TextArea_create);
	std::cout << "TextArea::create optcall => cdecl\n";
	std::cout << prettify(optcall->generateToDefault(textArea_create)) << "\n";
	std::cout << "TextArea::create cdecl => optcall\n";
	std::cout << prettify(optcall->generateFromDefault(textArea_create)) << "\n\n";

	auto membercall = std::make_unique<MembercallConvention>();
	auto textArea_init = AbstractFunction::from(&TextArea_init);
	std::cout << "TextArea::init membercall => cdecl\n";
	std::cout << prettify(membercall->generateToDefault(textArea_init)) << "\n";
	std::cout << "TextArea::init cdecl => membercall\n";
	std::cout << prettify(membercall->generateFromDefault(textArea_init)) << "\n\n";

	std::cout << "cconvTest0 optcall => cdecl\n";
	std::cout << prettify(conv->generateToDefault(func0)) << "\n";
	std::cout << "cconvTest0 cdecl => optcall\n";
	std::cout << prettify(conv->generateFromDefault(func0)) << "\n\n";

	std::cout << "cconvTest1 optcall => cdecl\n";
	std::cout << prettify(conv->generateToDefault(func1)) << "\n";
	std::cout << "cconvTest1 cdecl => optcall\n";
	std::cout << prettify(conv->generateFromDefault(func1)) << "\n\n";

	std::cout << "cconvTest2 optcall => cdecl\n";
	std::cout << prettify(conv->generateToDefault(func2)) << "\n";
	std::cout << "cconvTest2 cdecl => optcall\n";
	std::cout << prettify(conv->generateFromDefault(func2)) << "\n\n";
}
