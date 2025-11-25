cmake_minimum_required(VERSION 3.20)
project(vcrypto_test LANGUAGES C)

add_executable(vcrypto_test vcrypto_test.c)
target_link_libraries(vcrypto_test PRIVATE
  log_c
  crypto
  pthread
  ${DPDK_LIBRARIES}
  compiler_warnings
)

if(DPDK_FOUND AND DPDK_LIBRARY_DIRS)
  set_target_properties(vcrypto_test PROPERTIES
    BUILD_RPATH ${DPDK_LIBRARY_DIRS}
    INSTALL_RPATH ${DPDK_LIBRARY_DIRS}

  )
endif()
