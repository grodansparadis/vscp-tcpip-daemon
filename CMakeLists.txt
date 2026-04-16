# CMakeLists.txt
#
# VSCP TCP/IP Daemon — top-level build script.
#
# The daemon uses source files from the vscp submodule (third-party/vscp)
# wherever they are available, and falls back to src/ for files not yet
# present in the submodule.
#
# Configuration is read from a JSON file (vscpd.json).  The XML-based
# vscpd.conf format is no longer used.
#
# Build (Linux/macOS):
#   cmake -B build
#   cmake --build build
#
# Copyright (C) 2000-2026 Ake Hedman, the VSCP project
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.16...3.31)

project(vscp-tcpip-daemon
    VERSION 15.0.3
    DESCRIPTION "VSCP TCP/IP Daemon"
    LANGUAGES CXX C)

# ---- C++ standard ----
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

# Generate position-independent code (-fPIC on Unix)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Build output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin")

# ---- Options ----
option(VSCPD_BUILD_TESTS "Build unit tests" OFF)
option(VSCPD_ENABLE_SYSTEMD "Link against libsystemd for sd_notify support" ON)

# ---- Include module path from submodule (provides FindMosquitto, etc.) ----
list(APPEND CMAKE_MODULE_PATH
    "${CMAKE_CURRENT_SOURCE_DIR}/third-party/vscp/cmake/modules")

# ---- System libraries ----
include(GNUInstallDirs)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# ---- Add the VSCP common submodule ----
# This builds vscp_common, vscp_util and vscp_sqlite3 static libraries and
# exports all of their PUBLIC include directories (nlohmann/json, spdlog,
# mustache, OpenSSL, Mosquitto, Expat, CURL …) so that the daemon target
# inherits them automatically via target_link_libraries.
set(VSCP_INSTALL OFF CACHE BOOL "Skip install of vscp submodule targets" FORCE)
set(VSCP_BUILD_TESTS OFF CACHE BOOL "Skip tests inside vscp submodule" FORCE)
add_subdirectory(third-party/vscp)

# ---- Convenience alias for the submodule source root ----
set(VSCP_SUB "${CMAKE_CURRENT_SOURCE_DIR}/third-party/vscp")

# ---- Daemon source files ----
# Build the legacy daemon implementation using matching legacy dependencies.
set(VSCPD_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/linux/vscpd.cpp"
    "${VSCP_SUB}/src/vscp/common/clientlist.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_vscp_common/controlobject.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_vscp_common/tcpipsrv.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_vscp_common/interfacelist.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_vscp_common/userlist.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/devicethread.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/websrv.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_vscp_common/websocketsrv.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_vscp_common/restsrv.cpp"
    "${VSCP_SUB}/src/vscp/common/vscpremotetcpif.cpp"
    # Use vscphelper.cpp from the vscp submodule directly in the legacy daemon build.
    "${VSCP_SUB}/src/vscp/common/vscphelper.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_vscp_common/vscphelper_compat.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_vscp_common/automation.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/devicelist.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_vscp_common/mdf.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_vscp_common/guid.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_vscp_common/register.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_vscp_common/duktape_vscp_func.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_vscp_common/duktape_vscp_wrkthread.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_vscp_common/lua_vscp_func.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_vscp_common/lua_vscp_wrkthread.cpp"
    "${VSCP_SUB}/src/vscp/common/vscpdatetime.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/civetweb.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/sockettcp.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/dllist.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/configfile.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/crc.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/crc8.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/randpassword.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/third_party/duktape-2.5.0/src/duktape.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/third_party/LuaXML_lib.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/third_party/lua_all.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/vscp_aes.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/third_party/sqlite3-3.30.1/sqlite3.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/third_party/sqlite3math.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/fastpbkdf2.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/vscpmd5.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/vscpbase64.c"
)

# ---- Build the vscpd executable ----
add_executable(vscpd ${VSCPD_SOURCES})

# The legacy daemon headers and third-party imports live under src/daemon.
target_include_directories(vscpd
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/linux"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_vscp_common"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/third_party"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/third_party/nlohmann"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/third_party/lua-5.3.5/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/third_party/duktape-2.5.0/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/third_party/sqlite3-3.30.1"
        "${VSCP_SUB}/src/vscp/common"
        "${VSCP_SUB}/src/common"
        "${VSCP_SUB}/third_party/nlohmann/include"
        "${VSCP_SUB}/third_party/spdlog/include"
        "${VSCP_SUB}/third_party/mustache"
        "${VSCP_SUB}/third_party/maddy/include"
)

target_compile_definitions(vscpd PRIVATE
    USE_IPV6
    USE_WEBSOCKET
    USE_LUA
    USE_DUKTAPE
    USE_ZLIB
    USE_SERVER_STATS
)

target_link_libraries(vscpd
    PRIVATE
        Threads::Threads
    expat
    ssl
    crypto
    z
    rt
)

# Platform-specific extra libs
if(UNIX AND NOT APPLE)
    target_link_libraries(vscpd PRIVATE m dl)
endif()

# ---- Optional systemd sd_notify support ----
if(VSCPD_ENABLE_SYSTEMD)
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(SYSTEMD QUIET libsystemd)
        if(SYSTEMD_FOUND)
            target_compile_definitions(vscpd PRIVATE WITH_SYSTEMD)
            target_link_libraries(vscpd PRIVATE ${SYSTEMD_LIBRARIES})
            target_include_directories(vscpd PRIVATE ${SYSTEMD_INCLUDE_DIRS})
            message(STATUS "vscpd: systemd support enabled")
        else()
            message(STATUS "vscpd: systemd not found, sd_notify disabled")
        endif()
    endif()
endif()

# ---- Install rules ----
install(TARGETS vscpd
    RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# Install the JSON configuration template.
install(FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/install_files/unix/vscpd.json"
    DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/vscp"
)

# Install the sample systemd unit file if present.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/service/systemd/vscpd.service")
    install(FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/service/systemd/vscpd.service"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/systemd/system"
    )
endif()

# ---- Tests (optional) ----
if(VSCPD_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
