cmake_minimum_required(VERSION 3.21)

project(TulipHookRoot LANGUAGES CXX C)

if(NOT capstone)
	set(CAPSTONE_ARCHITECTURE_DEFAULT Off)
	set(CAPSTONE_X86_SUPPORT On)

	# did i say i hate cmake because that thing doesnt work
	set(CAPSTONE_ARM_SUPPORT Off)
	set(CAPSTONE_ARM64_SUPPORT Off)
	set(CAPSTONE_M68K_SUPPORT Off)
	set(CAPSTONE_MIPS_SUPPORT Off)
	set(CAPSTONE_PPC_SUPPORT Off)
	set(CAPSTONE_SPARC_SUPPORT Off)
	set(CAPSTONE_SYSZ_SUPPORT Off)
	set(CAPSTONE_XCORE_SUPPORT Off)
	set(CAPSTONE_TMS320C64X_SUPPORT Off)
	set(CAPSTONE_M680X_SUPPORT Off)
	set(CAPSTONE_EVM_SUPPORT Off)
	set(CAPSTONE_MOS65XX_SUPPORT Off)
	set(CAPSTONE_WASM_SUPPORT Off)
	set(CAPSTONE_BPF_SUPPORT Off)
	set(CAPSTONE_RISCV_SUPPORT Off)

	add_subdirectory(lib/capstone)
endif()

if(NOT keystone)

	set(LLVM_TARGETS_TO_BUILD "X86")
	add_compile_definitions(HAVE_DIRENT_H HAVE_FCNTL_H)

	add_subdirectory(lib/keystone)
endif()

add_subdirectory(src)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
	add_subdirectory(test)
endif()

target_include_directories(TulipHook INTERFACE 
	${TulipHookRoot_SOURCE_DIR}/include/tulip
)
