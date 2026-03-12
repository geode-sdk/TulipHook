cmake_minimum_required(VERSION 3.21)

project(TulipHookHooks LANGUAGES CXX C)

if(APPLE)
add_library(${PROJECT_NAME} SHARED HooksDef.cpp)
else()
add_library(${PROJECT_NAME} STATIC HooksDef.cpp)
endif()
