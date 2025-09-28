#pragma once

// clang-format off

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__) || defined(WIN64) || defined(_WIN64) || defined(__WIN64) && !defined(__CYGWIN__)

	#define TULIP_HOOK_WINDOWS 1
	#define TULIP_HOOK_SUPPORTED_PLATFORM 1

	#if defined(WIN64) || defined(_WIN64) || defined(__WIN64) && !defined(__CYGWIN__)
		#define TULIP_HOOK_X64 1
		#define TULIP_HOOK_MICROSOFT_X64_CONV 1
		#define TULIP_HOOK_DEFAULT_CONV __cdecl
	#else
		#define TULIP_HOOK_X86 1
		#define TULIP_HOOK_CDECL_CONV 1
		#define TULIP_HOOK_DEFAULT_CONV __cdecl
	#endif

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

	#define TULIP_HOOK_DARWIN 1

	#include <TargetConditionals.h>

	#if defined(TARGET_OS_MAC) && !defined(TARGET_OS_IPHONE)

		#define TULIP_HOOK_MACOS 1

		#define TULIP_HOOK_DEFAULT_CONV

		#if TARGET_CPU_ARM64
			#define TULIP_HOOK_ARMV8 1
			#define TULIP_HOOK_AAPCS64_CONV 1
			#define TULIP_HOOK_SUPPORTED_PLATFORM 1
		#elif TARGET_CPU_X86_64
			#define TULIP_HOOK_X64 1
			#define TULIP_HOOK_SYSTEMV_CONV 1
			#define TULIP_HOOK_SUPPORTED_PLATFORM 1
		#endif

		#ifdef TULIP_HOOK_EXPORTING
			#define TULIP_HOOK_DLL    __attribute__((visibility("default")))
		#else
			#define TULIP_HOOK_DLL
		#endif

	#elif TARGET_OS_IPHONE

		#define TULIP_HOOK_IOS 1

		#define TULIP_HOOK_DEFAULT_CONV
		#define TULIP_HOOK_AAPCS64_CONV 1
		
		#define TULIP_HOOK_ARMV8 1
		#define TULIP_HOOK_SUPPORTED_PLATFORM 1

		#ifdef TULIP_HOOK_EXPORTING
			#define TULIP_HOOK_DLL    __attribute__((visibility("default")))
		#else
			#define TULIP_HOOK_DLL
		#endif

	#endif

#endif

#if defined(__ANDROID__)

	#define TULIP_HOOK_POSIX 1

	#define TULIP_HOOK_ANDROID 1

	#define TULIP_HOOK_DEFAULT_CONV 

	#if defined(__arm__)
		#define TULIP_HOOK_ARMV7 1
		#define TULIP_HOOK_AAPCS_CONV 1
		#define TULIP_HOOK_SUPPORTED_PLATFORM 1
	#elif defined(__aarch64__)
		#define TULIP_HOOK_ARMV8 1
		#define TULIP_HOOK_AAPCS64_CONV 1
		#define TULIP_HOOK_SUPPORTED_PLATFORM 1
	#endif

	#ifdef TULIP_HOOK_EXPORTING
		#define TULIP_HOOK_DLL    __attribute__((visibility("default")))
	#else
		#define TULIP_HOOK_DLL
	#endif

#elif defined(__unix__)

	#define TULIP_HOOK_POSIX 1

	#define TULIP_HOOK_DEFAULT_CONV 

	#if defined(__arm__)
		#define TULIP_HOOK_ARMV7 1
		#define TULIP_HOOK_AAPCS_CONV 1
		#define TULIP_HOOK_SUPPORTED_PLATFORM 1
	#elif defined(__aarch64__)
		#define TULIP_HOOK_ARMV8 1
		#define TULIP_HOOK_AAPCS64_CONV 1
		#define TULIP_HOOK_SUPPORTED_PLATFORM 1
	#elif defined(__x86_64__)
		#define TULIP_HOOK_X64 1
		#define TULIP_HOOK_SYSTEMV_CONV 1
		#define TULIP_HOOK_SUPPORTED_PLATFORM 1
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
