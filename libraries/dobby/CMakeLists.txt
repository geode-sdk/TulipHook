cmake_minimum_required(VERSION 3.5)
project(Dobby)
enable_language(ASM)

file(GLOB DOBBY_SOURCES
    source/*.cc
    source/core/*.cc
    source/InstructionRelocation/*.cc
    source/MemoryAllocator/*.cc
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
