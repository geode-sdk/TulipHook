cmake_minimum_required(VERSION 3.21)

project(TulipHook LANGUAGES CXX C)

add_library(TulipHook STATIC
	Main.cpp
)

target_compile_features(TulipHook PUBLIC cxx_std_20)

target_include_directories(TulipHook PRIVATE
	${TulipHookRoot_SOURCE_DIR}/include/tulip
)

target_include_directories(TulipHook INTERFACE
	$<BUILD_INTERFACE:${TulipHookRoot_SOURCE_DIR}/include>
	$<BUILD_INTERFACE:${TulipHookRoot_SOURCE_DIR}/include/tulip>
)