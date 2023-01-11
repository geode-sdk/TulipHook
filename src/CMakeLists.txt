cmake_minimum_required(VERSION 3.21)

project(TulipHook LANGUAGES CXX C)

add_library(TulipHook STATIC
	CallingConvention.cpp
	Generator.cpp
	Handler.cpp
	Main.cpp
	Misc.cpp
	Pool.cpp
	Target.cpp
	Wrapper.cpp
	platform/DefaultConvention.cpp
	platform/MacosGenerator.cpp
	platform/MacosTarget.cpp
	platform/WindowsConvention.cpp
	platform/WindowsGenerator.cpp
	platform/WindowsTarget.cpp
	platform/X86Generator.cpp
)

target_compile_features(TulipHook PUBLIC cxx_std_20)

if(NOT capstone)
	set(CAPSTONE_ARCHITECTURE_DEFAULT Off)
	set(CAPSTONE_X86_SUPPORT On)

	# did i say i hate cmake because that thing doesnt work
	set(CAPSTONE_ARM_SUPPORT Off)
	set(CAPSTONE_ARM64_SUPPORT Off)
	set(CAPSTONE_M68K_SUPPORT Off)
	set(CAPSTONE_MIPS_SUPPORT Off)
	set(CAPSTONE_PPC_SUPPORT Off)
	set(CAPSTONE_SPARC_SUPPORT Off)
	set(CAPSTONE_SYSZ_SUPPORT Off)
	set(CAPSTONE_XCORE_SUPPORT Off)
	set(CAPSTONE_TMS320C64X_SUPPORT Off)
	set(CAPSTONE_M680X_SUPPORT Off)
	set(CAPSTONE_EVM_SUPPORT Off)
	set(CAPSTONE_MOS65XX_SUPPORT Off)
	set(CAPSTONE_WASM_SUPPORT Off)
	set(CAPSTONE_BPF_SUPPORT Off)
	set(CAPSTONE_RISCV_SUPPORT Off)

	set(CAPSTONE_X86_REDUCE On)
	set(CAPSTONE_X86_ATT_DISABLE On)

	CPMAddPackage("gh:capstone-engine/capstone#fee83fc")
endif()

if(NOT keystone)

	set(LLVM_TARGETS_TO_BUILD "X86")
	add_compile_definitions(HAVE_DIRENT_H HAVE_FCNTL_H)

	CPMAddPackage("gh:altalk23/keystone#2a6dc3f")
endif()

target_link_libraries(TulipHook PRIVATE capstone-static keystone)
target_link_libraries(TulipHook PUBLIC Result)
target_compile_definitions(TulipHook PRIVATE -DTULIP_HOOK_EXPORTING=1)

target_include_directories(TulipHook PRIVATE
	${TulipHookRoot_SOURCE_DIR}/include/tulip
	${capstone_SOURCE_DIR}/include
	${keystone_SOURCE_DIR}/include
)

target_include_directories(TulipHook INTERFACE
	$<BUILD_INTERFACE:${TulipHookRoot_SOURCE_DIR}/include>
)
