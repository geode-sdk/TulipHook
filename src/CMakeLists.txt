cmake_minimum_required(VERSION 3.21)

project(TulipHook LANGUAGES CXX C)

file(GLOB TULIP_HOOK_SOURCES
	*.cpp
	assembler/*.cpp
	convention/*.cpp
	generator/*.cpp
	target/*.cpp
)

add_library(${PROJECT_NAME} STATIC
	${TULIP_HOOK_SOURCES}
)

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)

if (MSVC)
	target_compile_options(${PROJECT_NAME} PUBLIC /EHsc)
endif ()

set(CAPSTONE_INSTALL Off)
set(CAPSTONE_ARCHITECTURE_DEFAULT Off)

if (WIN32 OR APPLE)
	set(CAPSTONE_X86_SUPPORT On)
	set(CAPSTONE_X86_REDUCE Off)
	set(CAPSTONE_X86_ATT_DISABLE On)
elseif (ANDROID)

endif()


CPMAddPackage("gh:geode-sdk/capstone#d2a14e5")

target_link_libraries(${PROJECT_NAME} PRIVATE capstone Dobby)
target_link_libraries(${PROJECT_NAME} PUBLIC Result)
target_compile_definitions(${PROJECT_NAME} PRIVATE -DTULIP_HOOK_EXPORTING=1)

message(STATUS "${Dobby_SOURCE_DIR}/source")

target_include_directories(${PROJECT_NAME} PRIVATE
	${TulipHookRoot_SOURCE_DIR}/include
	${TulipHookRoot_SOURCE_DIR}/include/tulip
	${capstone_SOURCE_DIR}/include
)

target_include_directories(${PROJECT_NAME} INTERFACE
	${TulipHookRoot_SOURCE_DIR}/include
)
