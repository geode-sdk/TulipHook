cmake_minimum_required(VERSION 3.21)

project(TulipHookRoot LANGUAGES CXX C)

include(cmake/CPM.cmake)

add_subdirectory(src)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
	add_subdirectory(test)
endif()

target_include_directories(TulipHook INTERFACE 
	${TulipHookRoot_SOURCE_DIR}/include
)
