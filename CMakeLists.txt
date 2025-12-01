cmake_minimum_required(VERSION 3.20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_COMPILER clang)
set(CMAKE_BUILD_TYPE Debug)
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

# using pkg-config to look for dpdk
# NOTE: in order to find dpdk using pkg-config
# it is recommended to search `libdpdk.pc`'s path and add the output
# into `PKG_CONFIG_PATH`
# e.g. `export PKG_CONFIG_PATH="/usr/local/lib64/pkgconfig:$PKG_CONFIG_PATH"`
find_package(PkgConfig REQUIRED)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(DPDK "libdpdk")
  if(DPDK_FOUND)
    list(JOIN DPDK_LIBRARY_DIRS ":" DPDK_RPATH)
    message(STATUS "found dpdk via pkg-config")
  else()
    message(WARNING
[=[
DPDK not found via pkg-config.
Please ensure 'libdpdk.pc' is installed and visible to pkg-config.
To fix this:
  1. Locate libdpdk.pc:
       find /usr -name libdpdk.pc 2>/dev/null
  2. Add its directory to PKG_CONFIG_PATH, e.g.:
       export PKG_CONFIG_PATH="/usr/local/lib64/pkgconfig:$PKG_CONFIG_PATH"
  3. Re-run cmake.
]=])
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

# common library , customed, used by both frontend and backend
add_library(common INTERFACE)
target_include_directories(common INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# local openssl
set(OPENSSL_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/openssl)
set(OPENSSL_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl_build)
set(OPENSSL_INCLUDE_DIR ${OPENSSL_BINARY_DIR}/include)
set(OPENSSL_LIB_DIR ${OPENSSL_BINARY_DIR}/lib)
set(OPENSSL_STAMP ${OPENSSL_BINARY_DIR}/.openssl_configured)
file(MAKE_DIRECTORY ${OPENSSL_BINARY_DIR})
if(NOT EXISTS ${OPENSSL_STAMP})
  add_custom_command(
    OUTPUT ${OPENSSL_STAMP}
    COMMAND ${CMAKE_COMMAND} -E chdir ${OPENSSL_SOURCE_DIR}
            ./Configure no-shared --prefix=${OPENSSL_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E touch ${OPENSSL_STAMP}
    COMMENT "Configuring OpenSSL (first-time build)"
    VERBATIM
  )
endif()
add_custom_target(build_openssl ALL
  COMMAND ${CMAKE_COMMAND} -E chdir ${OPENSSL_SOURCE_DIR} make -j$(nproc)
  COMMAND ${CMAKE_COMMAND} -E chdir ${OPENSSL_SOURCE_DIR} make install_sw
  COMMENT "Building OpenSSL before building vcrypto series"
)
message(STATUS "Built local OpenSSL")

  
# set compiler warning
add_library(compiler_warnings INTERFACE)
target_compile_options(compiler_warnings INTERFACE
    # -Wall
    # -Wextra
    # -Wpedantic
    # -Wconversion
    # -Wsign-conversion
    -Wshadow
    -Wdouble-promotion
    -Wformat=2
    -Wimplicit-fallthrough
    # -Wmissing-prototypes
    # -Wstrict-prototypes
    # -Werror
)

# when `RPATH` is not set, but with the following line
# program could also work~
# but without RPATH nor the following line, exe would not be
# able to find DLL at runtime
# this is not really making sense~~
# link_directories(/usr/local/lib64)

add_subdirectory(utils)
add_subdirectory(frontend)
add_subdirectory(backend)
add_subdirectory(tests)
