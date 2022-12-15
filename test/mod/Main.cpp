#include <Windows.h>
#include <string>
#include <iostream>
#include <tulip/TulipHook.hpp>

using namespace tulip::hook;

static uintptr_t getBase() {
	return reinterpret_cast<uintptr_t>(GetModuleHandleA(0));
}

class CCObject {
	virtual ~CCObject() = 0;
};

void logCCO(const char* name, CCObject* obj) {
	std::cout << name << ": " << obj << "\n";
	try {
		std::cout << "typeid: " << typeid(*obj).name() << "\n";
	} catch(...) {
		std::cout << "bad typeid\n";
	}
}

bool (__thiscall* MenuLayer_init_o)(CCObject*);
__declspec(noinline) bool __cdecl MenuLayer_init(CCObject* self) {
	std::cout << "MenuLayer::init hook\n";
	logCCO("self", self);

	std::cout << "Calling original\n";
	DebugBreak();
	auto ret = MenuLayer_init_o(self);
	std::cout << "Original returned: " << ret << "\n";
	
	return ret;
}

void (__thiscall* MenuLayer_onMoreGames_o)(CCObject*, CCObject*);
__declspec(noinline) void __cdecl MenuLayer_onMoreGames(CCObject* self, CCObject* sender) {
	std::cout << "MenuLayer::onMoreGames hook\n";
	logCCO("self", self);
	logCCO("sender", sender);

	// std::cout << "Calling original\n";
	// MenuLayer_onMoreGames_o(self, sender);

	// std::cout << "Original succesful!\n";
}

template<class T>
void makeHook(void* addr, T func) {
	auto metadata = tulip::hook::HandlerMetadata {
		.m_convention = std::make_shared<tulip::hook::ThiscallConvention>(),
		.m_abstract = tulip::hook::AbstractFunction::from(func)
	};

	std::cout << "## __thiscall -> __cdecl ##\n";
	std::cout << metadata.m_convention->generateIntoDefault(metadata.m_abstract) << "\n";

	std::cout << "## __cdecl stack fix ##\n";
	std::cout << metadata.m_convention->generateDefaultCleanup(metadata.m_abstract) << "\n";

	auto handle_result = tulip::hook::createHandler(addr, metadata);
	if (!handle_result) {
		std::cout << "Creating the handler failed L bozo" << std::endl;
		return;
	}
	auto handle = *handle_result;

	auto h_metadata = tulip::hook::HookMetadata {
		.m_priority = 0
	};

	tulip::hook::createHook(handle, (void*)(func), h_metadata);

	std::cout << "Hook created!" << std::endl;
}

DWORD WINAPI MainThread(void* module) {
	AllocConsole();
	freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);

	void* init_address = (void*)(getBase() + 0x1907b0);
	void* onMoreGames_address = (void*)(getBase() + 0x1919c0);
	MenuLayer_init_o = reinterpret_cast<decltype(MenuLayer_init_o)>(init_address);
	MenuLayer_onMoreGames_o = reinterpret_cast<decltype(MenuLayer_onMoreGames_o)>(onMoreGames_address);

	// std::cout << "Hooking MenuLayer::init\n";
	// makeHook(init_address, &MenuLayer_init);
	std::cout << "Hooking MenuLayer::onMoreGames\n";
	makeHook(onMoreGames_address, &MenuLayer_onMoreGames);

	return 0;
}

DWORD WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID) {
	if (reason == DLL_PROCESS_ATTACH) {
		CreateThread(NULL, 0, MainThread, module, 0, NULL);
	}
	return TRUE;
}

