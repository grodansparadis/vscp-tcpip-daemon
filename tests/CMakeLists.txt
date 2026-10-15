set(binary_protocol_sources ${VSCPD_SOURCES})
list(REMOVE_ITEM binary_protocol_sources "${PROJECT_SOURCE_DIR}/src/vscpd.cpp")

add_executable(binaryprotocol_test
    binaryprotocol.cpp
    binarytcp.cpp
    ${binary_protocol_sources}
)
target_include_directories(binaryprotocol_test PRIVATE
    $<TARGET_PROPERTY:vscpd,INCLUDE_DIRECTORIES>
)
target_compile_definitions(binaryprotocol_test PRIVATE
    $<TARGET_PROPERTY:vscpd,COMPILE_DEFINITIONS>
)
if(MSVC)
    target_compile_options(binaryprotocol_test PRIVATE /UNDEBUG)
else()
    target_compile_options(binaryprotocol_test PRIVATE -UNDEBUG)
endif()
target_link_libraries(binaryprotocol_test PRIVATE
    $<TARGET_PROPERTY:vscpd,LINK_LIBRARIES>
)
add_test(NAME binaryprotocol COMMAND binaryprotocol_test)
