cmake_minimum_required(VERSION 3.20)
project(vcrypto_engine_frontend LANGUAGES C)

add_library(vcrypto SHARED
  ciphers.c
  engine.c
  events.c
  md5.c
  protocol.c
  socket.c
  util.c
)

target_link_libraries(vcrypto PRIVATE
  crypto
  pthread
  ${DPDK_LIBRARIES}
  log_c
  klib
)

target_compile_definitions(vcrypto PRIVATE
  OPENSSL_ENABLE_VCRYPTO_SMALL_PACKET_CIPHER_OFFLOADS
  LOG_USE_COLOR
)

target_precompile_headers(vcrypto PRIVATE
  <klib/khash.h>
  <log.h>
)
set_target_properties(vcrypto PROPERTIES
  VERSION 1.0
  SOVERSION 1
  LIBRARY_OUTPUT_NAME "vcrypto"
  PREFIX ""
)

install(
  TARGETS vcrypto
  LIBRARY DESTINATION ${OPENSSL_ENGINE_DIR}
  COMPONENT vcrypto_engine
  RENAME "vcrypto.so"
)
