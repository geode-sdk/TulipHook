cmake_minimum_required(VERSION 3.21)

project(TulipHook LANGUAGES CXX C)

file(GLOB TULIP_HOOK_BASE_SOURCES
	*.cpp
	assembler/BaseAssembler.cpp
	convention/CallingConvention.cpp
	convention/DefaultConvention.cpp
	generator/Generator.cpp
	target/Target.cpp
)

if(WIN32)
	file(GLOB TULIP_HOOK_PLATFORM_SOURCES
		assembler/X86Assembler.cpp
		assembler/X64Assembler.cpp
		convention/WindowsConvention.cpp
		generator/X86Generator.cpp
		generator/X64Generator.cpp
		target/WindowsTarget.cpp
	)
elseif(APPLE)
	file(GLOB TULIP_HOOK_PLATFORM_SOURCES
		assembler/X86Assembler.cpp
		assembler/X64Assembler.cpp
		assembler/ArmV8Assembler.cpp
		generator/X86Generator.cpp
		generator/X64Generator.cpp
		generator/ArmV8Generator.cpp
		target/DarwinTarget.cpp
		target/MacosIntelTarget.cpp
		target/MacosArmV8Target.cpp
	)
elseif(ANDROID OR UNIX)
	file(GLOB TULIP_HOOK_PLATFORM_SOURCES
		assembler/ArmV7Assembler.cpp
		assembler/ArmV8Assembler.cpp
		generator/ArmV7Generator.cpp
		generator/ArmV8Generator.cpp
		target/PosixTarget.cpp
		target/PosixArmV7Target.cpp
		target/PosixArmV8Target.cpp
	)
else()
	message(FATAL_ERROR "Unsupported platform.")
endif()

add_library(${PROJECT_NAME} STATIC
	${TULIP_HOOK_BASE_SOURCES}
	${TULIP_HOOK_PLATFORM_SOURCES}
)

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)

if (MSVC)
	target_compile_options(${PROJECT_NAME} PUBLIC /EHsc)
endif ()

if (WIN32 OR APPLE)
	set(CAPSTONE_INSTALL Off)
	set(CAPSTONE_ARCHITECTURE_DEFAULT Off)

	set(CAPSTONE_X86_SUPPORT On)
	set(CAPSTONE_X86_REDUCE Off)
	set(CAPSTONE_X86_ATT_DISABLE On)

	CPMAddPackage("gh:geode-sdk/capstone#d2a14e5")
	target_link_libraries(${PROJECT_NAME} PRIVATE capstone)
	target_include_directories(${PROJECT_NAME} PRIVATE ${capstone_SOURCE_DIR}/include)
endif()
if(ANDROID OR UNIX OR APPLE)
	target_link_libraries(${PROJECT_NAME} PRIVATE Dobby)
	message(STATUS "${Dobby_SOURCE_DIR}/source")
endif()

target_link_libraries(${PROJECT_NAME} PUBLIC Result)
target_compile_definitions(${PROJECT_NAME} PRIVATE -DTULIP_HOOK_EXPORTING=1)

target_include_directories(${PROJECT_NAME} PRIVATE
	${TulipHookRoot_SOURCE_DIR}/include
	${TulipHookRoot_SOURCE_DIR}/include/tulip
)

target_include_directories(${PROJECT_NAME} INTERFACE
	${TulipHookRoot_SOURCE_DIR}/include
)
