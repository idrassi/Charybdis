# ==============================================================================
# Charybdis Block Cipher - CMake Build Configuration
#
# Author: Mounir IDRASSI <mounir.idrassi@amcrypto.jp>
# Version: 1.0
# Date: June 20, 2025
#
# This CMakeLists.txt configures the build system for the Charybdis block cipher
# reference implementation, AVX2-optimized version, constants generator, and
# test vector generator. It supports cross-platform builds (Windows, Linux, macOS)
# and allows specifying custom OpenSSL locations (see README.md).
#
# Targets:
#   - charybdis_test:         Self-tests and benchmarks
#   - charybdis_constants:    Constants generator (requires OpenSSL)
#   - charybdis_test_vector_gen: Test vector generator
#
# License: CC0 1.0 Universal (Public Domain Dedication)
# ==============================================================================


# Minimum required CMake version
cmake_minimum_required(VERSION 3.10)

# Project definition
project(Charybdis C)

# Set the C standard to C99
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# --- Define Build Options ---
option(CHARYBDIS_BUILD_TESTS "Build the test and benchmark executable" ON)
option(CHARYBDIS_BUILD_CONSTANTS_GEN "Build the constants generator utility" ON)
option(CHARYBDIS_BUILD_TEST_VECTOR_GEN "Build the test vector generator" ON)

# Include necessary CMake modules
include(CheckCCompilerFlag)

# --- Target: charybdis_test (Tests and Benchmarks) ---
if(CHARYBDIS_BUILD_TESTS)
    # Define source files for the test executable
    set(TEST_SOURCES
        src/charybdis.c
        src/charybdis.h
        src/charybdis_avx2.c
        src/charybdis_avx2.h
    )

    # Add the executable target
    add_executable(charybdis_test ${TEST_SOURCES})

    # Add the BENCHMARK definition
    target_compile_definitions(charybdis_test PRIVATE BENCHMARK)

    # Add -O3 for GCC/Clang
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(charybdis_test PRIVATE -O3)
    endif()

    # Check for and add AVX2 compiler flag portably
    check_c_compiler_flag("-mavx2" COMPILER_SUPPORTS_MAVX2)
    check_c_compiler_flag("/arch:AVX2" COMPILER_SUPPORTS_ARCH_AVX2)

    if(COMPILER_SUPPORTS_MAVX2)
        target_compile_options(charybdis_test PRIVATE -mavx2)
        message(STATUS "Compiler supports -mavx2. AVX2 optimizations enabled.")
    elseif(COMPILER_SUPPORTS_ARCH_AVX2)
        target_compile_options(charybdis_test PRIVATE /arch:AVX2)
        message(STATUS "Compiler supports /arch:AVX2. AVX2 optimizations enabled.")
    else()
        message(WARNING "AVX2 flag not supported by compiler. AVX2 implementation may not compile or run.")
    endif()
endif()


# --- Target: charybdis_constants (Constants Generator) ---
if(CHARYBDIS_BUILD_CONSTANTS_GEN)
    # Find the OpenSSL library
    find_package(OpenSSL REQUIRED)

    # Add the executable target
    add_executable(charybdis_constants tool/charybdis_constants.c)

    # Link against OpenSSL
    target_link_libraries(charybdis_constants PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()


# --- Target: charybdis_test_vector_gen (Test Vector Generator) ---
if(CHARYBDIS_BUILD_TEST_VECTOR_GEN)
    # This target is defined in charybdis.c under a macro guard.
    # We create a separate executable for it.
    add_executable(charybdis_test_vector_gen src/charybdis.c)

    # Add the necessary definition to enable the test vector generator code.
    target_compile_definitions(charybdis_test_vector_gen PRIVATE GENERATE_TEST_VECTORS)

    # Inform the user where to find the generated files
    message(STATUS "Test vector generator will be built. Run it from the project root to place files in test_vectors/")
endif()

