cmake_minimum_required(VERSION 3.21)

project(TulipHook LANGUAGES CXX C)

add_library(${PROJECT_NAME} STATIC
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
	platform/AndroidGenerator.cpp
	platform/AndroidTarget.cpp
	platform/WindowsConvention.cpp
	platform/WindowsGenerator.cpp
	platform/WindowsTarget.cpp
	platform/X86Generator.cpp
	assembler/BaseAssembler.cpp
	assembler/X86Assembler.cpp
	assembler/X64Assembler.cpp
)

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)

if (MSVC)
	target_compile_options(${PROJECT_NAME} PUBLIC /EHsc)
endif ()

set(CAPSTONE_INSTALL Off)
set(CAPSTONE_ARCHITECTURE_DEFAULT Off)

if (MSVC OR APPLE)
	set(CAPSTONE_X86_SUPPORT On)
	set(CAPSTONE_X86_REDUCE Off)
	set(CAPSTONE_X86_ATT_DISABLE On)
elseif (ANDROID)
	set(CAPSTONE_ARM_SUPPORT On)
endif()


CPMAddPackage("gh:geode-sdk/capstone#d2a14e5")

target_link_libraries(${PROJECT_NAME} PRIVATE capstone)
target_link_libraries(${PROJECT_NAME} PUBLIC Result)
target_compile_definitions(${PROJECT_NAME} PRIVATE -DTULIP_HOOK_EXPORTING=1)

target_include_directories(${PROJECT_NAME} PRIVATE
	${TulipHookRoot_SOURCE_DIR}/include
	${TulipHookRoot_SOURCE_DIR}/include/tulip
	${capstone_SOURCE_DIR}/include
)

target_include_directories(${PROJECT_NAME} INTERFACE
	${TulipHookRoot_SOURCE_DIR}/include
)
