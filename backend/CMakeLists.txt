cmake_minimum_required(VERSION 3.20)
project(vcrypto_engine_backend LANGUAGES C)

add_executable(${PROJECT_NAME}
  main.c
  loop.c
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
)

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
