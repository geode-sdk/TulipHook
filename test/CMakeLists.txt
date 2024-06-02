cmake_minimum_required(VERSION 3.21)

project(TulipHookTest LANGUAGES CXX C)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
CPMAddPackage("gh:google/googletest#f8d7d77")

enable_testing()

add_executable(${PROJECT_NAME} Assembler86.cpp Assembler64.cpp Hook.cpp)
target_link_libraries(${PROJECT_NAME} PUBLIC GTest::gtest_main TulipHook)

if(WIN32)
	# set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/INCREMENTAL:NO")

	if (CMAKE_SIZEOF_VOID_P EQUAL 8)
		add_executable(WinTest misc/WinTest.cpp)
		target_link_libraries(WinTest PUBLIC TulipHook)
		# set_target_properties(WinTest PROPERTIES LINK_FLAGS "/INCREMENTAL:NO")
	endif()

	if (CMAKE_SIZEOF_VOID_P EQUAL 4)
		add_library(TestMod SHARED misc/Mod.cpp)
		target_link_libraries(TestMod PUBLIC TulipHook)
	endif()
endif()

include(GoogleTest)
gtest_discover_tests(${PROJECT_NAME})
