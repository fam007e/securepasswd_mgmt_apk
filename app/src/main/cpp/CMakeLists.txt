cmake_minimum_required(VERSION 3.22.1)
project("securepasswd_mgmt_apk")

set(CORE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/core)
set(EXTERNAL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external)

# Argon2 (Vendored)
set(argon2_SOURCE_DIR ${EXTERNAL_DIR}/argon2)
add_library(argon2 STATIC
    ${argon2_SOURCE_DIR}/src/argon2.c
    ${argon2_SOURCE_DIR}/src/core.c
    ${argon2_SOURCE_DIR}/src/blake2/blake2b.c
    ${argon2_SOURCE_DIR}/src/thread.c
    ${argon2_SOURCE_DIR}/src/encoding.c
    ${argon2_SOURCE_DIR}/src/ref.c
)
target_include_directories(argon2 PUBLIC ${argon2_SOURCE_DIR}/include)

# OpenSSL (Vendored via openssl-cmake wrapper)
set(OPENSSL_SOURCE ${EXTERNAL_DIR}/openssl/openssl-src)
add_subdirectory(${EXTERNAL_DIR}/openssl EXCLUDE_FROM_ALL)

# SQLCipher (Vendored Amalgamation)
set(sqlcipher_SOURCE_DIR ${EXTERNAL_DIR}/sqlcipher)

# Shared sources for our core
add_library(${CMAKE_PROJECT_NAME} SHARED
    core_jni.cpp
    libsodium_shim.c
    sha1.c
    hmac.c
    ${sqlcipher_SOURCE_DIR}/sqlite3.c
    ${CORE_DIR}/database.c
    ${CORE_DIR}/key_derivation.c
    ${CORE_DIR}/password_generator.c
    ${CORE_DIR}/totp.c
    ${CORE_DIR}/sync_service.c
)

target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE
    SQLITE_HAS_CODEC
    SQLITE_TEMP_STORE=2
    SQLITE_ENABLE_FTS5
    SQLITE_ENABLE_RTREE
    SQLITE_EXTRA_INIT=sqlcipher_extra_init
    SQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown
)

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
    ${sqlcipher_SOURCE_DIR}
    ${CORE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${argon2_SOURCE_DIR}/include
)

target_link_libraries(${CMAKE_PROJECT_NAME}
    android
    log
    argon2
    OpenSSL::Crypto
)
