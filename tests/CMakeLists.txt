set(binary_protocol_sources ${VSCPD_SOURCES})
list(REMOVE_ITEM binary_protocol_sources "${PROJECT_SOURCE_DIR}/src/vscpd.cpp")

# Daemon sources compiled once and shared by the test executables
add_library(vscpd_test_objects OBJECT ${binary_protocol_sources})
target_include_directories(vscpd_test_objects PUBLIC
    $<TARGET_PROPERTY:vscpd,INCLUDE_DIRECTORIES>
)
target_compile_definitions(vscpd_test_objects PUBLIC
    $<TARGET_PROPERTY:vscpd,COMPILE_DEFINITIONS>
    MG_TLS=MG_TLS_OPENSSL
)
target_link_libraries(vscpd_test_objects PUBLIC
    $<TARGET_PROPERTY:vscpd,LINK_LIBRARIES>
)

# In-process tests of the binary protocol handler
add_executable(binaryprotocol_test
    binaryprotocol.cpp
    binarytcp.cpp
)
if(MSVC)
    target_compile_options(binaryprotocol_test PRIVATE /UNDEBUG)
else()
    target_compile_options(binaryprotocol_test PRIVATE -UNDEBUG)
endif()
target_link_libraries(binaryprotocol_test PRIVATE vscpd_test_objects)
add_test(NAME binaryprotocol COMMAND binaryprotocol_test)

# Black-box tests that start the real daemon and talk to it over TCP
if(NOT WIN32)
    add_executable(binaryserver_test binaryserver.cpp)
    target_link_libraries(binaryserver_test PRIVATE vscpd_test_objects)
    add_dependencies(binaryserver_test vscpd)
    add_test(NAME binaryserver COMMAND binaryserver_test $<TARGET_FILE:vscpd>)
    set_tests_properties(binaryserver PROPERTIES TIMEOUT 120)

    add_executable(tlsremote_test
        tlsremote.cpp
        "${vscp_SOURCE_DIR}/src/vscp/common/vscpremotetcpif.cpp"
    )
    target_link_libraries(tlsremote_test PRIVATE vscpd_test_objects)
    target_compile_definitions(tlsremote_test PRIVATE MG_TLS=MG_TLS_OPENSSL)
    add_dependencies(tlsremote_test vscpd)
    add_test(NAME tlsremote
        COMMAND tlsremote_test
                $<TARGET_FILE:vscpd>
                "${PROJECT_SOURCE_DIR}/install/certs/tcpip_server.crt"
                "${PROJECT_SOURCE_DIR}/install/certs/tcpip_server.key"
    )
    set_tests_properties(tlsremote PROPERTIES TIMEOUT 120)

    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        execute_process(
            COMMAND ${Python3_EXECUTABLE} -c "import cryptography, nacl"
            RESULT_VARIABLE python_modules_missing
            OUTPUT_QUIET ERROR_QUIET
        )
        if(python_modules_missing)
            message(STATUS "Python binary server tests skipped: "
                           "install the 'cryptography' and 'pynacl' modules")
        else()
            add_test(NAME binaryserver_python
                COMMAND ${Python3_EXECUTABLE}
                        ${CMAKE_CURRENT_SOURCE_DIR}/binary_server/test_binary_server.py
                        --vscpd $<TARGET_FILE:vscpd>
            )
            set_tests_properties(binaryserver_python PROPERTIES TIMEOUT 300)
        endif()
    endif()
endif()
