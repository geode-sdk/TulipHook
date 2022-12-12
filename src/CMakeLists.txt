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
	platform/DefaultConvention.cpp
	platform/MacosGenerator.cpp
	platform/MacosTarget.cpp
	platform/WindowsConvention.cpp
	platform/WindowsGenerator.cpp
	platform/WindowsTarget.cpp
	platform/X86Generator.cpp
)

target_compile_features(TulipHook PUBLIC cxx_std_20)

target_link_libraries(TulipHook PRIVATE capstone keystone)
target_compile_definitions(TulipHook PRIVATE -DTULIP_HOOK_EXPORTING=1)

target_include_directories(TulipHook PRIVATE
	${TulipHookRoot_SOURCE_DIR}/include/tulip
	${TulipHookRoot_SOURCE_DIR}/lib/capstone/include
	${TulipHookRoot_SOURCE_DIR}/lib/keystone/include
)

target_include_directories(TulipHook INTERFACE
	$<BUILD_INTERFACE:${TulipHookRoot_SOURCE_DIR}/include>
)
