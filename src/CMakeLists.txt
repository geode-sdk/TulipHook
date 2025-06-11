cmake_minimum_required(VERSION 3.21)

project(TulipHook LANGUAGES CXX C VERSION 2.4.2)

file(GLOB TULIP_HOOK_BASE_SOURCES
	*.cpp
	assembler/BaseAssembler.cpp
	convention/CallingConvention.cpp
	convention/DefaultConvention.cpp
	generator/Generator.cpp
	target/Target.cpp
)

if(WIN32)
	set(TULIP_HOOK_LINK_DOBBY Off)
	set(TULIP_HOOK_LINK_CAPSTONE On)
	file(GLOB TULIP_HOOK_PLATFORM_SOURCES
		assembler/X86Assembler.cpp
		assembler/X64Assembler.cpp
		convention/Windows32Convention.cpp
		convention/Windows64Convention.cpp
		generator/X86Generator.cpp
		generator/X64Generator.cpp
		target/Windows32Target.cpp
		target/Windows64Target.cpp
	)
elseif(APPLE)
	set(TULIP_HOOK_LINK_DOBBY On)
	set(TULIP_HOOK_LINK_CAPSTONE On)
	file(GLOB TULIP_HOOK_PLATFORM_SOURCES
		assembler/X86Assembler.cpp
		assembler/X64Assembler.cpp
		assembler/ArmV7Assembler.cpp
		assembler/ArmV8Assembler.cpp
		convention/MacosIntelConvention.cpp
		generator/X86Generator.cpp
		generator/X64Generator.cpp
		generator/ArmV7Generator.cpp
		generator/ArmV8Generator.cpp
		target/DarwinTarget.cpp
		target/MacosIntelTarget.cpp
		target/MacosM1Target.cpp
		target/iOSTarget.cpp
	)
elseif(ANDROID OR UNIX)
	set(TULIP_HOOK_LINK_DOBBY On)
	set(TULIP_HOOK_LINK_CAPSTONE Off)
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

if (TULIP_BUILD_DYNAMIC)
	add_library(${PROJECT_NAME} SHARED
		${TULIP_HOOK_BASE_SOURCES}
		${TULIP_HOOK_PLATFORM_SOURCES}
	)
	target_compile_definitions(${PROJECT_NAME} PUBLIC -DTULIP_HOOK_DYNAMIC=1)
else()
	add_library(${PROJECT_NAME} STATIC
		${TULIP_HOOK_BASE_SOURCES}
		${TULIP_HOOK_PLATFORM_SOURCES}
	)
endif()



target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)

if (MSVC)
	target_compile_options(${PROJECT_NAME} PUBLIC /EHsc)
endif ()

if (TULIP_HOOK_LINK_DOBBY)
	target_link_libraries(${PROJECT_NAME} PRIVATE Dobby)
	message(STATUS "${Dobby_SOURCE_DIR}/source")
endif()

if (TULIP_HOOK_LINK_CAPSTONE)
	set(CAPSTONE_INSTALL Off)
	set(CAPSTONE_ARCHITECTURE_DEFAULT Off)

	set(CAPSTONE_X86_SUPPORT On)
	set(CAPSTONE_X86_REDUCE Off)
	set(CAPSTONE_X86_ATT_DISABLE On)

	CPMAddPackage("gh:geode-sdk/capstone#d2a14e5")
	target_link_libraries(${PROJECT_NAME} PRIVATE capstone)
	target_include_directories(${PROJECT_NAME} PRIVATE ${capstone_SOURCE_DIR}/include)
endif()

target_link_libraries(${PROJECT_NAME} PUBLIC GeodeResult)
target_compile_definitions(${PROJECT_NAME} PRIVATE -DTULIP_HOOK_EXPORTING=1)

target_include_directories(${PROJECT_NAME} PRIVATE
	${TulipHookRoot_SOURCE_DIR}/include
	${TulipHookRoot_SOURCE_DIR}/include/tulip
)

target_include_directories(${PROJECT_NAME} INTERFACE
	${TulipHookRoot_SOURCE_DIR}/include
)
