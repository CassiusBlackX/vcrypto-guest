cmake_minimum_required(VERSION 3.10)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(vcrypto_guest)

add_library(log_c STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/log_c/src/log.c
)
target_include_directories(log_c PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/log_c/src
)
target_compile_definitions(log_c PRIVATE
  LOG_USE_COLOR
)

add_library(klib INTERFACE)
target_include_directories(klib INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/klib
)

add_subdirectory(frontend)
add_subdirectory(backend)
