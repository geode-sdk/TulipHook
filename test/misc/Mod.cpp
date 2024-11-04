#include "tulip/TulipHook.hpp"

#include <Windows.h>
#include <array>
#include <fstream>
#include <iostream>
#include <string>
#include <bit>

using namespace tulip::hook;

static uintptr_t getBase() {
	return reinterpret_cast<uintptr_t>(GetModuleHandleA(0));
}

static uintptr_t getCocosBase() {
	return reinterpret_cast<uintptr_t>(GetModuleHandleA("libcocos2d.dll"));
}

class CCObject {
	virtual ~CCObject() = 0;
};

struct CCPoint {
	float x, y;
	CCPoint(const CCPoint& point) : x(point.x), y(point.y) {}
};

std::ostream& operator<<(std::ostream& stream, CCPoint const& point) {
	return stream << "CCPoint(" << point.x << ", " << point.y << ")";
}

void logCCO(const char* name, CCObject* obj) {
	std::cout << name << ": " << obj << "\n";
	try {
		std::cout << "typeid: " << typeid(*obj).name() << "\n";
	} catch(...) {
		std::cout << "bad typeid\n";
	}
}

bool (__cdecl* MenuLayer_init_o)(CCObject*);
__declspec(noinline) bool __cdecl MenuLayer_init(CCObject* self) {
	std::cout << "MenuLayer::init hook\n";
	logCCO("self", self);

	std::cout << "Calling original\n";
	// DebugBreak();
	auto ret = MenuLayer_init_o(self);
	std::cout << "Original returned: " << ret << "\n";
	std::cout << std::endl;
	
	return ret;
}

void (__cdecl* MenuLayer_onMoreGames_o)(CCObject*, CCObject*);
__declspec(noinline) void __cdecl MenuLayer_onMoreGames(CCObject* self, CCObject* sender) {
	std::cout << "MenuLayer::onMoreGames hook";
	logCCO("self", self);
	logCCO("sender", sender);

	std::cout << "Calling original\n";
	MenuLayer_onMoreGames_o(self, sender);

	std::cout << "Original succesful!\n";
	std::cout << std::endl;
}

bool (__cdecl* GJDropDownLayer_init_o)(CCObject*, const char*, float);
__declspec(noinline) bool __cdecl GJDropDownLayer_init(CCObject* self, const char* title, float height) {
	std::cout << "GJDropDownLayer::init called" << std::endl;
	logCCO("self", self);
	std::cout << "title is " << title << std::endl;
	std::cout << "height is " << height << std::endl;
	height = 30.f;
	std::cout << "hehe gonna make it 30" << std::endl;
	auto ret = GJDropDownLayer_init_o(self, title, height);
	std::cout << "orig returned " << ret << std::endl;

	return ret;
}

using CoolString = std::array<int, 6>;

CCObject* (__cdecl* TextArea_create_o)(CoolString str, char const* font, float scale, float width, CCPoint anchor, float height, bool disableColor);
__declspec(noinline) CCObject* __cdecl TextArea_create(CoolString str, char const* font, float scale, float width, CCPoint anchor, float height, bool disableColor) {
	printf("TextArea::create hook.\n");
	printf("str: [%08x %08x %08x %08x %08x %08x]\n", str[0], str[1], str[2], str[3], str[4], str[5]);
	printf("font: %08x\n", (uintptr_t)font);
	printf("scale: %08x\n", std::bit_cast<uint32_t>(scale));
	printf("width: %08x\n", std::bit_cast<uint32_t>(width));
	printf("anchor: %08x %08x\n", std::bit_cast<uint32_t>(anchor.x), std::bit_cast<uint32_t>(anchor.y));
	printf("height: %08x\n", std::bit_cast<uint32_t>(height));
	printf("disableColor: %08x\n", disableColor);

	auto ret = TextArea_create_o(str, font, scale, width, anchor, height, disableColor);
	printf("succesfully called orginal");

	std::cout << "it returned " << ret << std::endl;
	logCCO("return", ret);

	return ret;
}

CCObject* (__cdecl* TextArea_create_o2)(CoolString str, char const* font, float scale, float width, CCPoint anchor, float height, bool disableColor);
__declspec(noinline) CCObject* __cdecl TextArea_create2(CoolString str, char const* font, float scale, float width, CCPoint anchor, float height, bool disableColor) {
	printf("TextArea::create hook #2.\n");
	printf("str: [%08x %08x %08x %08x %08x %08x]\n", str[0], str[1], str[2], str[3], str[4], str[5]);
	printf("font: %08x\n", (uintptr_t)font);
	printf("scale: %08x\n", std::bit_cast<uint32_t>(scale));
	printf("width: %08x\n", std::bit_cast<uint32_t>(width));
	printf("anchor: %08x %08x\n", std::bit_cast<uint32_t>(anchor.x), std::bit_cast<uint32_t>(anchor.y));
	printf("height: %08x\n", std::bit_cast<uint32_t>(height));
	printf("disableColor: %08x\n", disableColor);

	// lmao test
	
	// static const char* breh = "What's up guys Max0r here I would like to officially announce TulipHook works";

	// str[0] = reinterpret_cast<int>(breh);
	// str[4] = strlen(breh);
	// str[5] = strlen(breh);

	auto ret = TextArea_create_o2(str, font, scale, width, anchor, height, disableColor);
	printf("succesfully called orginal");

	std::cout << "it returned " << ret << std::endl;
	logCCO("return", ret);

	return ret;
}

CCObject* (__cdecl* CCLabelBMFont_create_o)(char const* text, char const* font);
__declspec(noinline) CCObject* __cdecl CCLabelBMFont_create(char const* text, char const* font) {
	std::cout << "CCLabelBMFont::create\n";
	std::cout << "text: " << text << std::endl;
	std::cout << "font: " << font << std::endl;

	auto ret = CCLabelBMFont_create_o("im mf mori calliope", font);
	std::cout << "returned: " << ret << std::endl;

	return ret;
}

template <class Conv, class T, class U>
void makeHookAndWrapper(void* target, T* func, U** orig) {
	using namespace tulip::hook;

	auto metadata = HandlerMetadata {
		.m_convention = std::make_shared<Conv>(),
		.m_abstract = AbstractFunction::from(func)
	};

	auto handleResult = createHandler(target, metadata);
	if (!handleResult) {
		std::cout << "unable to create handler: " << handleResult.unwrapErr() << "\n";
		exit(1);
	}
	auto handle = handleResult.unwrap();

	auto h_metadata = HookMetadata {
		.m_priority = 2
	};

	createHook(handle, reinterpret_cast<void*>(func), h_metadata);

	auto wrapperMetadata = WrapperMetadata {
		.m_convention = std::make_unique<Conv>(),
		.m_abstract = AbstractFunction::from(func)
	};

	auto wrapped = createWrapper(target, std::move(wrapperMetadata));

	if (wrapped.isErr()) {
		std::cout << "unable to create wrapper: " << wrapped.unwrapErr() << "\n";
		exit(1);
	}

	*reinterpret_cast<void**>(orig) = wrapped.unwrap();
};

DWORD WINAPI MainThread(void* module) {
	AllocConsole();
	freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);
	static std::ofstream out("CONOUT$", std::ios::out);
	std::cout.rdbuf(out.rdbuf());
	std::cout << std::boolalpha;

	void* init_address = (void*)(getBase() + 0x1907b0);
	void* onMoreGames_address = (void*)(getBase() + 0x1919c0);
	MenuLayer_init_o = reinterpret_cast<decltype(MenuLayer_init_o)>(init_address);
	MenuLayer_onMoreGames_o = reinterpret_cast<decltype(MenuLayer_onMoreGames_o)>(onMoreGames_address);

	std::cout << "Hooking MenuLayer::init\n";
	makeHookAndWrapper<ThiscallConvention>(init_address, &MenuLayer_init, &MenuLayer_init_o);

	std::cout << "Hooking MenuLayer::onMoreGames\n";
	makeHookAndWrapper<ThiscallConvention>(onMoreGames_address, &MenuLayer_onMoreGames, &MenuLayer_onMoreGames_o);
	
	std::cout << "Hooking GJDropDownLayer::init\n";
	makeHookAndWrapper<MembercallConvention>((void*)(getBase() + 0x113530), &GJDropDownLayer_init, &GJDropDownLayer_init_o);

	std::cout << "Hooking TextArea::create\n";
	makeHookAndWrapper<OptcallConvention>((void*)(getBase() + 0x33270), &TextArea_create, &TextArea_create_o);

	std::cout << "Hooking TextArea::create again\n";
	makeHookAndWrapper<OptcallConvention>((void*)(getBase() + 0x33270), &TextArea_create2, &TextArea_create_o2);
	
	std::cout << "Hooking CCLabelBMFont::create\n";
	makeHookAndWrapper<CdeclConvention>((void*)(getCocosBase() + 0x9c570), &CCLabelBMFont_create, &CCLabelBMFont_create_o);
	
	std::cout << std::endl;
	return 0;
}

DWORD WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID) {
	if (reason == DLL_PROCESS_ATTACH) {
		CreateThread(NULL, 0, MainThread, module, 0, NULL);
	}
	return TRUE;
}

