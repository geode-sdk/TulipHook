cmake_minimum_required(VERSION 3.21)

project(TulipHookHooks LANGUAGES CXX C)

add_library(${PROJECT_NAME} SHARED HooksDef.cpp)
