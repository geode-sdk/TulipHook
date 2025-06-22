SET(TARGET thumbv7neon-linux-gnueabihf)

SET(CMAKE_SYSTEM_PROCESSOR armv7a)
SET(CMAKE_SYSTEM_NAME Linux)

SET(CMAKE_CXX_COMPILER clang++)
SET(CMAKE_CXX_COMPILER_TARGET ${TARGET})
SET(CMAKE_C_COMPILER clang)
SET(CMAKE_C_COMPILER_TARGET ${TARGET})
SET(CMAKE_LINKER_TYPE LLD)

SET(CMAKE_C_FLAGS "-mthumb -mfloat-abi=softfp")
SET(CMAKE_CXX_FLAGS "-mthumb -mfloat-abi=softfp")

SET(CMAKE_FIND_ROOT_PATH "/usr/arm-linux-gnueabihf;/usr/arm-linux-gnueabi")
SET(CMAKE_CROSSCOMPILING_EMULATOR qemu-arm-static)
