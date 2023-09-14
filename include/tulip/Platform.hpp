#pragma once

// clang-format off

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)

	#define TULIP_HOOK_WINDOWS 1
	#define TULIP_HOOK_SUPPORTED_PLATFORM 1

	#define TULIP_HOOK_DEFAULT_CONV __cdecl

	#define TULIP_HOOK_X86 1

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

		#define TULIP_HOOK_MACOS 1
		#define TULIP_HOOK_SUPPORTED_PLATFORM 1

		#define TULIP_HOOK_DEFAULT_CONV

		#define TULIP_HOOK_X64 1

		#ifdef TULIP_HOOK_EXPORTING
			#define TULIP_HOOK_DLL    __attribute__((visibility("default")))
		#else
			#define TULIP_HOOK_DLL
		#endif

	#endif

#endif

#if defined(__ANDROID__)

	#define TULIP_HOOK_ANDROID 1
	#define TULIP_HOOK_SUPPORTED_PLATFORM 1

	#define TULIP_HOOK_DEFAULT_CONV 

	#if defined(__arm__)
		#define TULIP_HOOK_ARMV7 1
	#elif defined(__aarch64__)
		#define TULIP_HOOK_ARMV8 1
	#endif

	#ifdef TULIP_HOOK_EXPORTING
		#define TULIP_HOOK_DLL    __attribute__((visibility("default")))
	#else
		#define TULIP_HOOK_DLL
	#endif
	
#endif

#if !defined(TULIP_HOOK_SUPPORTED_PLATFORM)

	#error "Unsupported Platform!"

#endif

namespace tulip::hook {}

// clang-format on