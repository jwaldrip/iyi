cmake_minimum_required(VERSION 3.20)
project(jit_reservation_probe LANGUAGES C CXX)

find_package(LLVM 20.1.7 EXACT REQUIRED CONFIG)
message(STATUS "Using LLVM ${LLVM_PACKAGE_VERSION} at ${LLVM_DIR}")

add_executable(jit_reservation_probe probe.cpp)
target_include_directories(jit_reservation_probe SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(jit_reservation_probe PRIVATE ${LLVM_DEFINITIONS} LLVM_ENABLE_TEST_HOOKS=1)
target_compile_features(jit_reservation_probe PRIVATE cxx_std_17)

# Locate LLVM-C library (import lib for LLVM-C.dll)
find_library(LLVM_C_LIB NAMES LLVM-C HINTS ${LLVM_LIBRARY_DIRS} ${LLVM_DIR}/../../lib ${LLVM_DIR}/../../../lib)
if(NOT LLVM_C_LIB)
  message(STATUS "LLVM_C_LIB not found via find_library, falling back to LLVM-C target/name")
  set(LLVM_C_LIB LLVM-C)
else()
  message(STATUS "Found LLVM-C library at: ${LLVM_C_LIB}")
endif()

target_link_libraries(jit_reservation_probe PRIVATE ${LLVM_C_LIB} kernel32 ntdll)
