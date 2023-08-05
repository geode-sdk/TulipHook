cmake_minimum_required(VERSION 3.21)

project(TulipHookTestAssembler LANGUAGES CXX C)

add_executable(TulipHookTestAssembler Main.cpp)
target_link_libraries(TulipHookTestAssembler PUBLIC TulipHook)
