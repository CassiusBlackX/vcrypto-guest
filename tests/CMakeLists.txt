cmake_minimum_required(VERSION 3.20)
project(vcrypto_test LANGUAGES C)

add_executable(dltest dltest.c)
target_compile_definitions(dltest PRIVATE
  "PROJECT_BUILD_DIR=\"${CMAKE_BINARY_DIR}\""
)

add_executable(sym_cipher_test vcrypto_sym_cipher_test.c)
target_link_libraries(sym_cipher_test PRIVATE
  log_c
  pthread
  ${DPDK_LIBRARIES}
  compiler_warnings
  crypto
)
target_compile_definitions(sym_cipher_test PRIVATE
  "PROJECT_BUILD_DIR=\"${CMAKE_BINARY_DIR}\""
)

if(DPDK_FOUND AND DPDK_LIBRARY_DIRS)
  set_target_properties(sym_cipher_test PROPERTIES
    BUILD_RPATH ${DPDK_LIBRARY_DIRS}
    INSTALL_RPATH ${DPDK_LIBRARY_DIRS}
  )
endif()

add_executable(asym_cipher_test vcrypto_asym_cipher_test.c)
target_link_libraries(asym_cipher_test PRIVATE
  log_c
  pthread
  ${DPDK_LIBRARIES}
  compiler_warnings
  crypto
)
target_compile_definitions(asym_cipher_test PRIVATE
  "CMAKE_CURRENT_SOURCE_PATH=\"${CMAKE_CURRENT_SOURCE_DIR}\""
)

if(DPDK_FOUND AND DPDK_LIBRARY_DIRS)
  set_target_properties(asym_cipher_test PROPERTIES
    BUILD_RPATH ${DPDK_LIBRARY_DIRS}
    INSTALL_RPATH ${DPDK_LIBRARY_DIRS}
  )
endif()

