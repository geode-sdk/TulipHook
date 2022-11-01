
#include <Windows.h>
#include <string>
#include <iostream>
#include <TulipHook.hpp>

using namespace tulip::hook;

static HandlerHandle HANDLER_HANDLE;
static HookHandle HOOK_HANDLE;

struct CCPoint {
    float x;
    float y;
};

static uintptr_t getBase() {
    return reinterpret_cast<uintptr_t>(GetModuleHandleA(0));
}

void* (__cdecl* TextArea_create_o)(std::string, const char*, float, float, CCPoint, float, bool);
void* __cdecl TextArea_create(
    std::string str, const char* font, float width, float height,
    CCPoint anchor, float scale, bool disableColor
) {
    std::cout << "TextArea::create\n";

    std::cout << "str: " << str << "\n";
    std::cout << "font: " << font << "\n";
    std::cout << "width: " << width << "\n";
    std::cout << "height: " << height << "\n";
    std::cout << "anchor.x: " << anchor.x << "\n";
    std::cout << "anchor.y: " << anchor.y << "\n";
    std::cout << "scale: " << scale << "\n";
    std::cout << "disableColor: " << disableColor << "\n";

    return nullptr;
}

DWORD MainThread(LPVOID lpParam) {
    AllocConsole();
    freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);

	HandlerMetadata meta;
    meta.m_convention = std::make_unique<OptcallConvention>();
    meta.m_abstract = AbstractFunction::from<decltype(TextArea_create)>();

    auto handler = createHandler(
        reinterpret_cast<void*>(getBase() + 0x33270),
        meta
    );

	if (handler.isErr()) {
		MessageBoxA(
            nullptr,
            ("Unable to create handler: " + handler.unwrapErr()).c_str(),
            "uh oh",
            MB_ICONERROR
        );
		return 1;
	}

    HANDLER_HANDLE = handler.unwrap();

    // HOOK_HANDLE = createHook(
    //     HANDLER_HANDLE,
    //     reinterpret_cast<void*>(&TextArea_create),
    //     HookMetadata()
    // );
    TextArea_create_o = reinterpret_cast<decltype(TextArea_create_o)>(getBase() + 0x33270);

	return S_OK;
}

DWORD WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved) {
	switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            CreateThread(NULL, 0x1000, reinterpret_cast<LPTHREAD_START_ROUTINE>(&MainThread), NULL, 0, NULL);
            break;

        default:
            break;
	}
	return TRUE;
}

