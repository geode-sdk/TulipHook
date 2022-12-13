#include <Windows.h>
#include <string>
#include <iostream>
#include <tulip/TulipHook.hpp>

using namespace tulip::hook;

static uintptr_t getBase() {
	return reinterpret_cast<uintptr_t>(GetModuleHandleA(0));
}

__declspec(noinline) bool __cdecl MenuLayer_init(void* me) {
	std::cout << "MenuLayer init called with " << me << std::endl;
	return false;
}

DWORD WINAPI MainThread(void* module) {
	AllocConsole();
	freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);

	void* address = (void*)(getBase() + 0x1907B0);

	auto metadata = tulip::hook::HandlerMetadata {
		.m_convention = std::make_shared<tulip::hook::ThiscallConvention>(),
		.m_abstract = tulip::hook::AbstractFunction::from(&MenuLayer_init)
	};

	auto handle_result = tulip::hook::createHandler(address, metadata);
	if (!handle_result) {
		std::cout << "creating the handler failed L" << std::endl;
		return 1;
	}
	auto handle = *handle_result;

	auto h_metadata = tulip::hook::HookMetadata {
		.m_priority = 0
	};

	tulip::hook::createHook(handle, (void*)(&MenuLayer_init), h_metadata);

	std::cout << "hook created!" << std::endl;

	return 0;
}

DWORD WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID) {
	if (reason == DLL_PROCESS_ATTACH) {
		CreateThread(NULL, 0, MainThread, module, 0, NULL);
	}
	return TRUE;
}

