add_library(core_lib STATIC
    key_derivation.c
    database.c
    totp.c
    pwned_check.c
    platform_paths.c
    password_generator.c
)

# Include directories
target_include_directories(core_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# SQLCipher handling
if(WIN32)
    # On Windows, try to find the include directory if not already set
    if(NOT SQLCIPHER_INCLUDE_DIRS)
        find_path(SQLCIPHER_INCLUDE_DIRS NAMES sqlite3.h sqlcipher/sqlite3.h)
    endif()
endif()

# Include directories for dependencies
target_include_directories(core_lib PUBLIC
    ${LIBSODIUM_INCLUDE_DIRS}
    ${ARGON2_INCLUDE_DIRS}
    ${SQLCIPHER_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

# Link libraries
target_link_libraries(core_lib PUBLIC
    ${LIBSODIUM_LIBRARIES}
    ${ARGON2_LIBRARIES}
    ${CURL_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)

# SQLCipher header check and linking
# We prefer targets (sqlcipher::sqlcipher from vcpkg or PkgConfig::SQLCIPHER)
if(TARGET sqlcipher::sqlcipher OR TARGET PkgConfig::SQLCIPHER)
    set(_sqlcipher_target "")
    if(TARGET sqlcipher::sqlcipher)
        set(_sqlcipher_target sqlcipher::sqlcipher)
    else()
        set(_sqlcipher_target PkgConfig::SQLCIPHER)
    endif()

    message(STATUS "Linking core_lib against SQLCipher target: ${_sqlcipher_target}")
    target_link_libraries(core_lib PUBLIC ${_sqlcipher_target})

    # We still need to check which header to use in the code (#include <sqlite3.h> etc)
    # Get include paths from the target to assist check_include_file
    get_target_property(_target_includes ${_sqlcipher_target} INTERFACE_INCLUDE_DIRECTORIES)
    set(CMAKE_REQUIRED_INCLUDES ${_target_includes} ${SQLCIPHER_INCLUDE_DIRS})
elseif(SQLCIPHER_LIBRARIES)
    message(STATUS "Linking core_lib against SQLCipher libraries: ${SQLCIPHER_LIBRARIES}")
    target_link_libraries(core_lib PUBLIC ${SQLCIPHER_LIBRARIES})

    # If using variables, ensure include dirs are set
    if(NOT SQLCIPHER_INCLUDE_DIRS)
        foreach(lib ${SQLCIPHER_LIBRARIES})
            if(EXISTS "${lib}")
                get_filename_component(lib_dir "${lib}" DIRECTORY)
                get_filename_component(root_dir "${lib_dir}" DIRECTORY)
                if(EXISTS "${root_dir}/include")
                    target_include_directories(core_lib PUBLIC "${root_dir}/include")
                    list(APPEND SQLCIPHER_INCLUDE_DIRS "${root_dir}/include")
                endif()
            endif()
        endforeach()
    endif()
    set(CMAKE_REQUIRED_INCLUDES ${SQLCIPHER_INCLUDE_DIRS})
else()
    # Manual fallback for unusual environments
    find_library(SQLCIPHER_LIBRARY NAMES sqlcipher)
    if(SQLCIPHER_LIBRARY)
        message(STATUS "Found SQLCipher library via find_library: ${SQLCIPHER_LIBRARY}")
        target_link_libraries(core_lib PUBLIC ${SQLCIPHER_LIBRARY})

        get_filename_component(lib_dir "${SQLCIPHER_LIBRARY}" DIRECTORY)
        get_filename_component(root_dir "${lib_dir}" DIRECTORY)
        if(EXISTS "${root_dir}/include")
            target_include_directories(core_lib PUBLIC "${root_dir}/include")
            set(CMAKE_REQUIRED_INCLUDES "${root_dir}/include")
        endif()
    else()
        message(FATAL_ERROR "Could not find sqlcipher library")
    endif()
endif()

# Header check for selection logic in database.c
include(CheckIncludeFile)
check_include_file("sqlcipher/sqlite3.h" HAVE_SQLCIPHER_SUBDIR)
check_include_file("sqlcipher.h" HAVE_SQLCIPHER_HEADER)

if(HAVE_SQLCIPHER_SUBDIR)
    target_compile_definitions(core_lib PRIVATE HAVE_SQLCIPHER_SUBDIR)
elseif(HAVE_SQLCIPHER_HEADER)
    target_compile_definitions(core_lib PRIVATE HAVE_SQLCIPHER_HEADER)
endif()

# Platform-specific link directories (mostly for Linux/macOS)
if(NOT WIN32)
    target_link_directories(core_lib PUBLIC
        ${LIBSODIUM_LIBRARY_DIRS}
        ${ARGON2_LIBRARY_DIRS}
    )
endif()

target_compile_definitions(core_lib PRIVATE SQLITE_HAS_CODEC)
