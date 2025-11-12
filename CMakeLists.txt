cmake_minimum_required(VERSION 3.20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_COMPILER clang)
project(vcrypto_guest LANGUAGES C)

option(RELEASE_MODE "Build for release: static link third-party libs" OFF)
message(STATUS "Build Mode: ${CMAKE_BUILD_TYPE}")
message(STATUS "Release Mode (static Link): ${RELEASE_MODE}")

# log.c library for logging in vcrypto_guest
add_library(log_c STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/log_c/src/log.c
)
target_include_directories(log_c PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/log_c/src
)
target_compile_definitions(log_c PRIVATE
  LOG_USE_COLOR
)

if(NOT RELEASE_MODE)
  add_library(log_c_shared SHARED 
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/log_c/src/log.c
  )
  target_include_directories(log_c_shared PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/log_c/src
  )
  target_compile_definitions(log_c_shared PRIVATE
    LOG_USE_COLOR
  )
endif()

# klib library for containers in vcrypto_guest
add_library(klib INTERFACE)
target_include_directories(klib INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/klib
)

find_package(PkgConfig REQUIRED)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(DPDK "libdpdk")
  if(DPDK_FOUND)
    message(STATUS "found dpdk via pkg-config")
  else()
    message(WARN "unable to find dpdk via pkg-config")
  endif()
endif()

# xxHash library for hash
add_library(xxHash STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/xxHash/xxhash.c
)
target_include_directories(xxHash PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/xxHash
)

if(NOT RELEASE_MODE)
  add_library(xxHash_shared SHARED 
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/xxHash/xxhash.c
  )
  target_include_directories(log_c_shared PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/xxHash
  )
endif()


add_subdirectory(utils)
add_subdirectory(frontend)
add_subdirectory(backend)

