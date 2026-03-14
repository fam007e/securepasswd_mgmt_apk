cmake_minimum_required(VERSION 3.25.1)
project("securepasswd_mgmt_apk")

set(CORE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/core)

include(FetchContent)

# Argon2 is small and easy to build from source
FetchContent_Declare(
    argon2
    GIT_REPOSITORY https://github.com/P-H-C/phc-winner-argon2.git
    GIT_TAG        master
)
FetchContent_GetProperties(argon2)
if(NOT argon2_POPULATED)
    FetchContent_Populate(argon2)
    add_library(argon2 STATIC
        ${argon2_SOURCE_DIR}/src/argon2.c
        ${argon2_SOURCE_DIR}/src/core.c
        ${argon2_SOURCE_DIR}/src/blake2/blake2b.c
        ${argon2_SOURCE_DIR}/src/thread.c
        ${argon2_SOURCE_DIR}/src/encoding.c
        ${argon2_SOURCE_DIR}/src/ref.c
    )
    target_include_directories(argon2 PUBLIC ${argon2_SOURCE_DIR}/include)
endif()

# Fetch OpenSSL for Android (Self-contained repo supporting 3.x)
FetchContent_Declare(
    openssl_cmake
    URL https://github.com/jimmy-park/openssl-cmake/archive/refs/tags/3.6.1.tar.gz
)
FetchContent_GetProperties(openssl_cmake)
if(NOT openssl_cmake_POPULATED)
    FetchContent_Populate(openssl_cmake)
endif()

add_subdirectory(${openssl_cmake_SOURCE_DIR} ${openssl_cmake_BINARY_DIR})

# Fetch SQLCipher amalgamation (using user-suggested ZIP)
FetchContent_Declare(
    sqlcipher
    URL https://github.com/chehrlic/sqlcipher-amalgamation/archive/refs/tags/v4.13.0.tar.gz
)
FetchContent_GetProperties(sqlcipher)
if(NOT sqlcipher_POPULATED)
    FetchContent_Populate(sqlcipher)
endif()

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
    ${CORE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${argon2_SOURCE_DIR}/include
    ${sqlcipher_SOURCE_DIR}
)

target_link_libraries(${CMAKE_PROJECT_NAME}
    android
    log
    argon2
    OpenSSL::Crypto
)
