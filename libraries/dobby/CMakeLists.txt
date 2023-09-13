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

target_include_directories(Dobby PUBLIC
    external
    include
    source
    source/dobby
)
