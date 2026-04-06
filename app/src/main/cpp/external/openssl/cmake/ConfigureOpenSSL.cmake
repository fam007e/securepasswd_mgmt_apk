include(CMakeParseArguments)

function(parse_configdata KEY VALUES)
    if(NOT EXISTS "${OPENSSL_CONFIGDATA}")
        return()
    endif()

    if(KEY STREQUAL "perlargv")
        # Process a multi-line config
        file(READ ${OPENSSL_CONFIGDATA} CONFIGDATA)
        string(REGEX MATCH "[\" ]${KEY}[^\]]*" OUTPUT ${CONFIGDATA})
        string(REGEX REPLACE "[\" ]${KEY}[\" ]" "" OUTPUT ${OUTPUT})
        string(REGEX MATCHALL "\"[^\"]+\"" OUTPUT ${OUTPUT})
        list(TRANSFORM OUTPUT REPLACE "\"" "")
    else()
        file(STRINGS ${OPENSSL_CONFIGDATA} OUTPUT REGEX "[\" ]${KEY}[\" ]+=>")
        string(REGEX REPLACE "[\" ]${KEY}[\" ]" "" OUTPUT ${OUTPUT})
        string(REGEX MATCH "\"[^\"]*\"" OUTPUT ${OUTPUT})
        string(REPLACE "\"" "" OUTPUT ${OUTPUT})
    endif()

    if(KEY STREQUAL "options")
        string(REPLACE " " ";" ${VALUES} ${OUTPUT})
    else()
        set(${VALUES} ${OUTPUT})
    endif()

    set(${VALUES} ${${VALUES}} PARENT_SCOPE)
    return()
endfunction()

function(lookup_makefile STRING KEY VALUES)
    string(REGEX MATCH "\n${KEY}=[^\n]*" OUTPUT "${STRING}")
    string(REGEX REPLACE "\n${KEY}=[ ]*" "" ${VALUES} "${OUTPUT}")

    set(${VALUES} ${${VALUES}} PARENT_SCOPE)
    return()
endfunction()

function(parse_makefile FILE KEY VALUES)
    if(NOT EXISTS "${FILE}")
        message(FATAL_ERROR "Couldn't find Makefile")
    endif()

    file(READ ${FILE} MAKEFILE)
    string(REGEX REPLACE "[\\]\n" "" MAKEFILE "${MAKEFILE}")
    lookup_makefile("${MAKEFILE}" ${KEY} OUTPUT)

    # Variable expansion
    while(TRUE)
        string(REGEX MATCH "[\$][^\)]*[\)]" VARIABLE "${OUTPUT}")

        if("${VARIABLE}" STREQUAL "")
            break()
        endif()

        string(REGEX REPLACE "[\$\(\)]" "" SUBKEY "${VARIABLE}")
        lookup_makefile("${MAKEFILE}" ${SUBKEY} SUBVALUE)
        string(REPLACE "${VARIABLE}" "${SUBVALUE}" OUTPUT "${OUTPUT}")
    endwhile()

    string(REPLACE "\"" "" OUTPUT "${OUTPUT}")
    string(REGEX REPLACE "[ ]+" ";" ${VALUES} "${OUTPUT}")
    list(REMOVE_ITEM ${VALUES} "")

    set(${VALUES} ${${VALUES}} PARENT_SCOPE)
    return()
endfunction()

function(apply_ccache FILE)
    if(NOT EXISTS "${FILE}")
        message(FATAL_ERROR "Couldn't find Makefile")
    endif()

    file(READ ${FILE} MAKEFILE)

    if(OPENSSL_USE_CCACHE)
        find_program(CCACHE ccache)
        if(CCACHE)
            string(REPLACE "\nCC=" "\nCC=ccache " MAKEFILE "${MAKEFILE}")
        endif()
    endif()

    # Inject path mapping for reproducibility without leaking it into config strings
    # We need to go 6 levels up from app/src/main/cpp/external/openssl to reach the root
    get_filename_component(REPRO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../" ABSOLUTE)
    
    # Comprehensive prefix mapping for all supported compilers/assemblers
    set(REPRO_FLAGS 
        "-ffile-prefix-map=${REPRO_ROOT}=."
        "-ffile-prefix-map=${CMAKE_ANDROID_NDK}=NDK"
        "-fmacro-prefix-map=${REPRO_ROOT}=."
        "-fmacro-prefix-map=${CMAKE_ANDROID_NDK}=NDK"
        "-fdebug-prefix-map=${REPRO_ROOT}=."
        "-fdebug-prefix-map=${CMAKE_ANDROID_NDK}=NDK"
    )
    
    # Convert list to space-separated string
    string(REPLACE ";" " " REPRO_FLAGS_STR "${REPRO_FLAGS}")
    
    # Inject into configuration flags
    string(REPLACE "\nCNF_CFLAGS=" "\nCNF_CFLAGS=${REPRO_FLAGS_STR} " MAKEFILE "${MAKEFILE}")
    string(REPLACE "\nCNF_CXXFLAGS=" "\nCNF_CXXFLAGS=${REPRO_FLAGS_STR} " MAKEFILE "${MAKEFILE}")
    string(REPLACE "\nCNF_CPPFLAGS=" "\nCNF_CPPFLAGS=${REPRO_FLAGS_STR} " MAKEFILE "${MAKEFILE}")
    string(REPLACE "\nCNF_ASFLAGS=" "\nCNF_ASFLAGS=${REPRO_FLAGS_STR} " MAKEFILE "${MAKEFILE}")
    
    # Also inject into user flags to be certain
    string(REPLACE "\nCFLAGS=" "\nCFLAGS=${REPRO_FLAGS_STR} " MAKEFILE "${MAKEFILE}")
    string(REPLACE "\nCXXFLAGS=" "\nCXXFLAGS=${REPRO_FLAGS_STR} " MAKEFILE "${MAKEFILE}")
    string(REPLACE "\nCPPFLAGS=" "\nCPPFLAGS=${REPRO_FLAGS_STR} " MAKEFILE "${MAKEFILE}")
    string(REPLACE "\nASFLAGS=" "\nASFLAGS=${REPRO_FLAGS_STR} " MAKEFILE "${MAKEFILE}")

    if(MSVC)
        string(REPLACE "/Zi /Fdossl_static.pdb " "" MAKEFILE "${MAKEFILE}")
        string(REPLACE "/Zi /Fddso.pdb " "" MAKEFILE "${MAKEFILE}")
        string(REPLACE "/Zi /Fdapp.pdb " "" MAKEFILE "${MAKEFILE}")
    endif()

    file(WRITE ${FILE} "${MAKEFILE}")
endfunction()

function(configure_openssl)
    cmake_parse_arguments(
        CONFIGURE
        "" # options
        "FILE;BUILD_DIR" # one_value_keywords
        "COMMAND;OPTIONS" # multi_value_keywords
        ${ARGN}
    )

    message(STATUS "Curruent configure options : ${CONFIGURE_OPTIONS}")

    # Find previous configure results
    set(OPENSSL_CONFIGDATA ${CONFIGURE_BUILD_DIR}/configdata.pm CACHE INTERNAL "Results of OpenSSL configuration")
    parse_configdata("perlargv" CONFIGURE_OPTIONS_OLD)

    if(NOT "${CONFIGURE_OPTIONS_OLD}" STREQUAL "")
        if(CONFIGURE_OPTIONS STREQUAL CONFIGURE_OPTIONS_OLD)
            message(STATUS "Found previous configure results. Don't perform configuration")
            return()
        endif()

        if(IS_DIRECTORY ${CONFIGURE_BUILD_DIR})
            message(STATUS "Previous configure options : ${CONFIGURE_OPTIONS_OLD}")
            message(STATUS "Configure options are changed. Clean build directory")
            file(REMOVE_RECURSE ${CONFIGURE_BUILD_DIR})
        endif()
    endif()

    if(NOT IS_DIRECTORY ${CONFIGURE_BUILD_DIR})
        file(MAKE_DIRECTORY ${CONFIGURE_BUILD_DIR})
    endif()

    message(STATUS "Configure OpenSSL")
    find_program(OPENSSL_CONFIGURE_TOOL perl REQUIRED)
    list(APPEND CONFIGURE_COMMAND ${OPENSSL_CONFIGURE_TOOL} ${CONFIGURE_FILE} ${CONFIGURE_OPTIONS})

    if(OPENSSL_CONFIGURE_VERBOSE)
        set(VERBOSE_OPTION "")
    else()
        set(VERBOSE_OPTION OUTPUT_QUIET)
    endif()

    execute_process(
        COMMAND ${CONFIGURE_COMMAND}
        WORKING_DIRECTORY ${CONFIGURE_BUILD_DIR}
        ${VERBOSE_OPTION}
        COMMAND_ERROR_IS_FATAL ANY
    )

    if(OPENSSL_CONFIGURE_VERBOSE)
        execute_process(
            COMMAND ${OPENSSL_CONFIGURE_TOOL} configdata.pm -d
            WORKING_DIRECTORY ${CONFIGURE_BUILD_DIR}
            COMMAND_ERROR_IS_FATAL ANY
        )
    endif()

    # Modify Makefile
    find_file(
        OPENSSL_MAKEFILE
        NAMES makefile Makefile
        PATHS ${CONFIGURE_BUILD_DIR}
        REQUIRED
        NO_DEFAULT_PATH
    )
    apply_ccache(${OPENSSL_MAKEFILE})

    if(WIN32 AND NOT OPENSSL_BUILD_VERBOSE)
        file(READ ${OPENSSL_MAKEFILE} MAKEFILE)
        string(REPLACE "/W3" "/W0" MAKEFILE "${MAKEFILE}")
        file(WRITE ${OPENSSL_MAKEFILE} "${MAKEFILE}")
    endif()

    set(OPENSSL_MAKEFILE ${OPENSSL_MAKEFILE} PARENT_SCOPE)
endfunction()