cmake_minimum_required(VERSION 3.21)

project(TulipHookRoot LANGUAGES CXX C)

include(cmake/CPM.cmake)

option(TULIP_LINK_SOURCE "Link to TulipHook source files, including external libs" OFF)

if (TULIP_LINK_SOURCE)
	add_subdirectory(src)
endif()

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
	add_subdirectory(test)
endif()


CPMAddPackage("gh:bitwizeshift/result#a97e66b")

add_library(TulipHookInclude INTERFACE)
target_include_directories(TulipHookInclude INTERFACE
	${TulipHookRoot_SOURCE_DIR}/include
)

target_link_libraries(TulipHookInclude INTERFACE Result)