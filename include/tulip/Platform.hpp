#pragma once

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)

	#define TULIP_HOOK_WINDOWS
	#define TULIP_HOOK_SUPPORTED_PLATFORM

	#define TULIP_HOOK_DEFAULT_CONV __cdecl

	#ifdef TULIP_HOOK_DYNAMIC
		#ifdef TULIP_HOOK_EXPORTING
			#define TULIP_HOOK_DLL    __declspec(dllexport)
		#else
			#define TULIP_HOOK_DLL    __declspec(dllimport)
		#endif
	#else
		#define TULIP_HOOK_DLL
	#endif

#endif

#if defined(__APPLE__)

	#include <TargetConditionals.h>

	#if TARGET_OS_MAC

		#define TULIP_HOOK_MACOS
		#define TULIP_HOOK_SUPPORTED_PLATFORM

		#define TULIP_HOOK_DEFAULT_CONV

		#ifdef TULIP_HOOK_EXPORTING
			#define TULIP_HOOK_DLL    __attribute__((visibility("default")))
		#else
			#define TULIP_HOOK_DLL
		#endif

	#endif

#endif


#if !defined(TULIP_HOOK_SUPPORTED_PLATFORM)

	#error "Unsupported Platform!"

#endif

namespace tulip::hook {}