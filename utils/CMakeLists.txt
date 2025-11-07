cmake_minimum_required(VERSION 3.20)
project(vcrypto_engine_socket)

add_library(${PROJECT_NAME} STATIC
  socket.c
)
target_link_libraries(${PROJECT_NAME} PUBLIC
  log_c
)
target_include_directories(${PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
)

if(NOT RELEASE_MODE)
  add_library(vcrypto_engine_socket_shared SHARED
    socket.c
  )
  target_link_libraries(vcrypto_engine_socket_shared PUBLIC
    log_c_shared
  )
  target_include_directories(vcrypto_engine_socket_shared PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}
  )
endif()
