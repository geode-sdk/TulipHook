cmake_minimum_required(VERSION 3.21)

project(TulipHookTest LANGUAGES CXX C)

add_executable(TulipHookTest Main.cpp)
target_link_libraries(TulipHookTest PUBLIC TulipHook)