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
  pthread
  ${DPDK_LIBRARIES}
  klib
  common
  compiler_warnings
)

if(DPDK_FOUND AND DPDK_LIBRARY_DIRS)
  set_target_properties(vcrypto PROPERTIES
    BUILD_RPATH ${DPDK_LIBRARY_DIRS}
    INSTALL_RPATH ${DPDK_LIBRARY_DIRS}
  )
  message(STATUS "adding dpdk_library_dirs into vcrypto.so's rpath")
endif()

if(NOT RELEASE_MODE)
  target_link_libraries(vcrypto PRIVATE
    log_c_shared
    vcrypto_engine_socket_shared
    xxHash_shared
    ${OPENSSL_LIB_DIR}/libcrypto.a # local openssl crypto lib
  )
  add_dependencies(vcrypto build_openssl)
  target_include_directories(vcrypto PRIVATE
    ${OPENSSL_INCLUDE_DIR}
  )
else()
  target_link_libraries(vcrypto PRIVATE
    log_c
    vcrypto_engine_socket
    xxHash
    crypto # system default openssl crypto library
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

# for debug, soft link to local openssl ossl-modules dir
add_custom_command(TARGET vcrypto
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E create_symlink
    $<TARGET_FILE:vcrypto>
    ${OPENSSL_LIB_DIR}/ossl-modules/vcrypto.so
  COMMENT "Creating symlink in ossl-moidules for vcrypto"
)

install(
  TARGETS vcrypto
  LIBRARY DESTINATION ${OPENSSL_ENGINE_DIR}
  COMPONENT vcrypto_engine
  RENAME "vcrypto.so"
)
