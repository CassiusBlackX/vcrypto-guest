cmake_minimum_required(VERSION 3.20)
project(vcrypto_engine_frontend LANGUAGES C)

add_library(vcrypto SHARED
  provider.c
  events.c
  protocol.c
)
target_sources(vcrypto PRIVATE
  aes_cbc.c
)

target_link_libraries(vcrypto PRIVATE
  crypto
  pthread
  ${DPDK_LIBRARIES}
  klib
)

if(NOT RELEASE_NODE)
  target_link_libraries(vcrypto PRIVATE
    log_c_shared
    vcrypto_engine_socket_shared
  )
else()
  target_link_libraries(vcrypto PRIVATE
    log_c
    vcrypto_engine_socket
  )
endif()

target_compile_definitions(vcrypto PRIVATE
  OPENSSL_ENABLE_VCRYPTO_SMALL_PACKET_CIPHER_OFFLOADS
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
