cmake_minimum_required(VERSION 3.21)

project(TulipHookRoot LANGUAGES CXX C)

include(cmake/CPM.cmake)

option(TULIP_LINK_SOURCE "Link to TulipHook source files, including external libs" OFF)

if(TULIP_LINK_SOURCE OR PROJECT_IS_TOP_LEVEL)
	if (ANDROID)
		add_subdirectory(libraries/dobby)
	endif()
	add_subdirectory(src)
endif()

if(PROJECT_IS_TOP_LEVEL)
	if (NOT ANDROID)
		add_subdirectory(test)
	endif()
endif()

CPMAddPackage("gh:bitwizeshift/result#a97e66b")

add_library(TulipHookInclude INTERFACE)
target_include_directories(TulipHookInclude INTERFACE
	${TulipHookRoot_SOURCE_DIR}/include
)

target_link_libraries(TulipHookInclude INTERFACE Result)
