cmake_minimum_required(VERSION 3.21)

if(WIN32)
    project(TulipHookTestMod LANGUAGES CXX C)

    add_library(TulipHookTestMod SHARED Main.cpp)
    target_link_libraries(TulipHookTestMod PUBLIC TulipHook)
endif()
