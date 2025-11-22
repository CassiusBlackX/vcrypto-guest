cmake_minimum_required(VERSION 3.20)
project(vcrypto_test LANGUAGES C)

add_executable(vcrypto_test vcrypto_test.c)
target_link_libraries(vcrypto_test PRIVATE
  log_c
  crypto
  pthread
)
