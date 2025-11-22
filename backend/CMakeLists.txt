cmake_minimum_required(VERSION 3.20)
project(vcrypto_engine_backend LANGUAGES C)

add_executable(${PROJECT_NAME}
  main.c
  event.c
  protocol.c
  mempool.c
  cdev.c
  sess.c
  hashmap.c
)

target_link_libraries(${PROJECT_NAME} PRIVATE
  crypto
  pthread
  ${DPDK_LIBRARIES}
  klib
  common
)

if(DPDK_FOUND AND DPDK_LIBRARY_DIRS)
  set_target_properties(${PROJECT_NAME} PROPERTIES
    BUILD_RPATH ${DPDK_LIBRARY_DIRS}
    INSTALL_RPATH ${DPDK_LIBRARY_DIRS}
  )
  message(STATUS "adding dpdk_library_dirs into ${PROJECT_NAME}'s rpath")
endif()

if(NOT RELEASE_NODE)
  target_link_libraries(${PROJECT_NAME} PRIVATE
    log_c_shared
    vcrypto_engine_socket_shared
  )
else()
  target_link_libraries(${PROJECT_NAME} PRIVATE
    log_c
    vcrypto_engine_socket
  )
endif()
