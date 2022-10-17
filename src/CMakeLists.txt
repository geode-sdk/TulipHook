cmake_minimum_required(VERSION 3.21)

project(TulipHook LANGUAGES CXX C)

add_library(TulipHook STATIC
	Main.cpp
	Handler.cpp
	Pool.cpp
	CallingConvention.cpp
	platform/WindowsCallingConvention.cpp
	platform/MacosTarget.cpp
	platform/MacosHandler.cpp
	platform/WindowsHandler.cpp
)

target_compile_features(TulipHook PUBLIC cxx_std_20)

target_link_libraries(TulipHook PRIVATE capstone keystone)
target_compile_definitions(TulipHook PRIVATE -DTULIP_HOOK_EXPORTING)

target_include_directories(TulipHook PRIVATE
	${TulipHookRoot_SOURCE_DIR}/include/tulip
	${TulipHookRoot_SOURCE_DIR}/lib/capstone/include
	${TulipHookRoot_SOURCE_DIR}/lib/keystone/include
)

target_include_directories(TulipHook INTERFACE
	$<BUILD_INTERFACE:${TulipHookRoot_SOURCE_DIR}/include>
	$<BUILD_INTERFACE:${TulipHookRoot_SOURCE_DIR}/include/tulip>
)