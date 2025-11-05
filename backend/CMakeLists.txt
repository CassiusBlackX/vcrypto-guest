cmake_minimum_required(VERSION 3.20)
project(vcrypto_engine_backend LANGUAGES C)

add_executable(${PROJECT_NAME}
  main.c
  util.c
  loop.c
  protocol.c
  mempool.c
  cdev.c
  sess.c
  socket.c
)

target_link_libraries(${PROJECT_NAME} PRIVATE
  crypto
  pthread
  ${DPDK_LIBRARIES}
  log_c
  klib
)

target_compile_definitions(${PROJECT_NAME} PRIVATE
  LOG_USE_COLOR
)

target_precompile_headers(${PROJECT_NAME} PRIVATE
  <klib/khash.h>
  <log.h>
)
