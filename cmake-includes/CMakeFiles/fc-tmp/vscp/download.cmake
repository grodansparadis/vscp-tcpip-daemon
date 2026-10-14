cmake_minimum_required(VERSION ${CMAKE_VERSION}) # this file comes with cmake

message(VERBOSE "Executing download step for vscp")

block(SCOPE_FOR VARIABLES)

include("/home/akhe/development/VSCP/vscp-tcpip-daemon/cmake-includes/CMakeFiles/fc-stamp/vscp/download-vscp.cmake")
include("/home/akhe/development/VSCP/vscp-tcpip-daemon/cmake-includes/CMakeFiles/fc-stamp/vscp/verify-vscp.cmake")
include("/home/akhe/development/VSCP/vscp-tcpip-daemon/cmake-includes/CMakeFiles/fc-stamp/vscp/extract-vscp.cmake")


endblock()
