cmake_minimum_required(VERSION 3.20)
project(vcrypto_test LANGUAGES C)

add_executable(${PROJECT_NAME} vcrypto_test.c)
target_link_libraries(${PROJECT_NAME} PRIVATE
  log_c
  pthread
  ${DPDK_LIBRARIES}
  compiler_warnings
  crypto
)
target_compile_definitions(${PROJECT_NAME} PRIVATE
  "PROJECT_BUILD_DIR=\"${CMAKE_BINARY_DIR}\""
)

if(DPDK_FOUND AND DPDK_LIBRARY_DIRS)
  set_target_properties(${PROJECT_NAME} PROPERTIES
    BUILD_RPATH ${DPDK_LIBRARY_DIRS}
    INSTALL_RPATH ${DPDK_LIBRARY_DIRS}
  )
endif()
