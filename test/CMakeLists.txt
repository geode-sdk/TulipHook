cmake_minimum_required(VERSION 3.21)

project(TulipHookTest LANGUAGES CXX C)

add_executable(TulipHookTest Main.cpp)
target_link_libraries(TulipHookTest PUBLIC TulipHook)

if(WIN32)
	set_target_properties(TulipHookTest PROPERTIES LINK_FLAGS "/INCREMENTAL:NO")

	add_executable(TulipHookWinTest WinTest.cpp)
	target_link_libraries(TulipHookWinTest PUBLIC TulipHook)
	set_target_properties(TulipHookWinTest PROPERTIES LINK_FLAGS "/INCREMENTAL:NO")
endif()

add_subdirectory(mod)
