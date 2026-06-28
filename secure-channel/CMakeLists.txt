cmake_minimum_required(VERSION 3.10)
project(SecureChannel VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(MBEDTLS REQUIRED mbedtls)

include_directories(include)
include_directories(${MBEDTLS_INCLUDE_DIRS})

add_library(secure_channel_core
    src/crypto.cpp
    src/network.cpp
    src/handshake.cpp
    src/record.cpp
    src/common.cpp
    src/vault.cpp
    src/key_manager.cpp
    src/encryption_engine.cpp
)
message(STATUS "MBEDTLS_LIBRARIES: ${MBEDTLS_LIBRARIES}")
message(STATUS "MBEDTLS_INCLUDE_DIRS: ${MBEDTLS_INCLUDE_DIRS}")

target_link_libraries(secure_channel_core ${MBEDTLS_LIBRARIES})

# This is redundant because of include_directories above, but harmless
target_include_directories(secure_channel_core PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

add_executable(secure_client src/client/main.cpp src/client/client_handlers.cpp)
target_link_libraries(secure_client secure_channel_core mbedtls mbedcrypto mbedx509)

add_executable(secure_server src/server/main.cpp src/server/server_handlers.cpp)
target_link_libraries(secure_server secure_channel_core mbedtls mbedcrypto mbedx509)

enable_testing()
add_subdirectory(tests)