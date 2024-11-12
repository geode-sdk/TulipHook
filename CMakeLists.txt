cmake_minimum_required(VERSION 3.25)

set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT Embedded)
cmake_policy(SET CMP0141 NEW)

project(TulipHookRoot LANGUAGES CXX C)

include(cmake/CPM.cmake)

option(TULIP_LINK_SOURCE "Link to TulipHook source files, including external libs" OFF)

if(TULIP_LINK_SOURCE OR PROJECT_IS_TOP_LEVEL)
	if(ANDROID OR UNIX OR APPLE)
		add_subdirectory(libraries/dobby)
	endif()
	add_subdirectory(src)
endif()

if(PROJECT_IS_TOP_LEVEL AND NOT TULIP_DONT_BUILD_TESTS)
	add_subdirectory(test)
endif()

if (NOT TARGET GeodeResult)
	CPMAddPackage("gh:geode-sdk/result@1.2.0")
endif()

add_library(TulipHookInclude INTERFACE)
target_include_directories(TulipHookInclude INTERFACE
	${TulipHookRoot_SOURCE_DIR}/include
)

target_link_libraries(TulipHookInclude INTERFACE GeodeResult)
