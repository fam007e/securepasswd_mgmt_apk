cmake_minimum_required(VERSION 3.22.1)
project("securepasswd_mgmt_apk")

# Suppress noisy macro redefinition warnings globally (e.g., __PIC__)
add_compile_options(-Wno-macro-redefined)

# Secure path-independent absolute mappings for reproducibility
get_filename_component(REAL_PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../" ABSOLUTE)

# Strip all possible path leaks (Source, Macros, and Debug Symbols)
# Using CMAKE_ANDROID_NDK which is set by AGP
add_compile_options("-ffile-prefix-map=${REAL_PROJECT_ROOT}=.")
add_compile_options("-ffile-prefix-map=${CMAKE_ANDROID_NDK}=NDK")
add_compile_options("-fmacro-prefix-map=${REAL_PROJECT_ROOT}=.")
add_compile_options("-fmacro-prefix-map=${CMAKE_ANDROID_NDK}=NDK")
add_compile_options("-fdebug-prefix-map=${REAL_PROJECT_ROOT}=.")
add_compile_options("-fdebug-prefix-map=${CMAKE_ANDROID_NDK}=NDK")

# Remove non-deterministic ELF sections and strings
add_compile_options("-fno-ident")
add_compile_options("-fno-asynchronous-unwind-tables")

# Linker flags for reproducibility
add_link_options("-Wl,--build-id=none")
add_link_options("-Wl,--hash-style=gnu")
add_link_options("-Wl,--gc-sections")
add_link_options("-Wl,--no-undefined")
add_link_options("-Wl,-z,noexecstack")
add_link_options("-Wl,-z,relro")
add_link_options("-Wl,-z,now")

# CMAKE_CURRENT_SOURCE_DIR is app/src/main/cpp
set(PROJECT_ROOT ${REAL_PROJECT_ROOT})
set(CORE_DIR ${PROJECT_ROOT}/core)
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
# Pass reproducibility environment to OpenSSL build
set(ENV{SOURCE_DATE_EPOCH} "1711075200")
add_subdirectory(${EXTERNAL_DIR}/openssl EXCLUDE_FROM_ALL)

# SQLCipher (Vendored Amalgamation)
set(sqlcipher_SOURCE_DIR ${EXTERNAL_DIR}/sqlcipher)

# Shared sources for our core
add_library(${CMAKE_PROJECT_NAME} SHARED
    core_jni.cpp
    ${sqlcipher_SOURCE_DIR}/sqlite3.c
    ${CORE_DIR}/libsodium_shim.c
    ${CORE_DIR}/sha1.c
    ${CORE_DIR}/hmac.c
    ${CORE_DIR}/database.c
    ${CORE_DIR}/key_derivation.c
    ${CORE_DIR}/password_generator.c
    ${CORE_DIR}/totp.c
    ${CORE_DIR}/sync_service.c
    ${CORE_DIR}/pwned_check.c
    ${CORE_DIR}/platform_paths.c
)

target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE
    SQLITE_HAS_CODEC
    SQLITE_TEMP_STORE=2
    SQLITE_ENABLE_FTS5
    SQLITE_ENABLE_RTREE
    SQLITE_EXTRA_INIT=sqlcipher_extra_init
    SQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown
    __ANDROID__
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
