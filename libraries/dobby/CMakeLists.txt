cmake_minimum_required(VERSION 3.5)
project(Dobby)
enable_language(ASM)

file(GLOB DOBBY_SOURCES
    source/core/arch/*.cc
    source/core/assembler/*.cc
    source/core/codegen/*.cc
    source/InstructionRelocation/arm/*.cc
    source/InstructionRelocation/arm64/*.cc
    source/MemoryAllocator/*.cc
    source/MemoryAllocator/CodeBuffer/*.cc
)

add_library(${PROJECT_NAME} STATIC
    ${DOBBY_SOURCES}
)

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/external
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/source
    ${CMAKE_CURRENT_SOURCE_DIR}/source/dobby
)
