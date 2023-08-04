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
	assembler/BaseAssembler.cpp
	assembler/x86Assembler.cpp
	assembler/x64Assembler.cpp
)

target_compile_features(TulipHook PUBLIC cxx_std_20)


set(CAPSTONE_X86_SUPPORT On)
set(CAPSTONE_INSTALL Off)
set(CAPSTONE_ARCHITECTURE_DEFAULT Off)

set(CAPSTONE_X86_SUPPORT On)
set(CAPSTONE_X86_REDUCE Off)
set(CAPSTONE_X86_ATT_DISABLE On)

CPMAddPackage("gh:capstone-engine/capstone#a4df92e")

set(LLVM_TARGETS_TO_BUILD "X86")
CPMAddPackage("gh:altalk23/keystone#ee876d2")

target_link_libraries(TulipHook PRIVATE capstone keystone)
target_link_libraries(TulipHook PUBLIC Result)
target_compile_definitions(TulipHook PRIVATE -DTULIP_HOOK_EXPORTING=1)

target_include_directories(TulipHook PRIVATE
	${TulipHookRoot_SOURCE_DIR}/include
	${TulipHookRoot_SOURCE_DIR}/include/tulip
	${capstone_SOURCE_DIR}/include
	${keystone_SOURCE_DIR}/include
)

target_include_directories(TulipHook INTERFACE
	${TulipHookRoot_SOURCE_DIR}/include
)