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
set(CMAKE_CXX_STANDARD 17)
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
find_package(OpenSSL REQUIRED)
find_package(EXPAT REQUIRED)
find_package(ZLIB REQUIRED)

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
set(DUKTAPE_SUB "${CMAKE_CURRENT_SOURCE_DIR}/third-party/duktape")
set(DUKTAPE_AMALG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third-party/duktape-amalgamation")

# Use a platform-appropriate daemon entrypoint.
if(WIN32)
    set(VSCPD_MAIN_SOURCE "${VSCP_SUB}/src/vscp/daemon/vscpd.cpp")
else()
    set(VSCPD_MAIN_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/linux/vscpd.cpp")
endif()

# ---- Daemon source files ----
# Build the daemon using vscp submodule for common functionality.
set(VSCPD_SOURCES
    "${VSCPD_MAIN_SOURCE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/controlobject.cpp"
    "${VSCP_SUB}/src/vscp/common/tcpipsrv.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/interfacelist.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/userlist.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/devicethread.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/websrv.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/websocketsrv.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/restsrv.cpp"
    # Use vscphelper_compat from daemon.
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/vscphelper_compat.cpp"
    "${VSCP_SUB}/src/vscp/common/automation.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/devicelist.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/mdf.cpp"
    # Duktape and Lua scripting extensions
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/duktape_vscp_func.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/duktape_vscp_wrkthread.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/lua_vscp_func.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/lua_vscp_wrkthread.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/civetweb.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/sockettcp.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/dllist.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/configfile.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/crc.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/crc8.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/randpassword.cpp"
    "${DUKTAPE_AMALG_DIR}/duktape.c"
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

# The daemon headers and third-party imports live under src/daemon.
target_include_directories(vscpd
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/linux"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/third_party"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/third_party/nlohmann"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/third_party/lua-5.3.5/src"
        "${DUKTAPE_AMALG_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/legacy_common/third_party/sqlite3-3.30.1"
        "${VSCP_SUB}/src/vscp/common"
        "${VSCP_SUB}/src/common"
        "${VSCP_SUB}/third_party/nlohmann/include"
        "${VSCP_SUB}/third_party/spdlog/include"
        "${VSCP_SUB}/third_party/mustache"
        "${VSCP_SUB}/third_party/maddy/include"
)

if(WIN32)
    target_include_directories(vscpd
        PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/win32helpers"
            "${VSCP_SUB}/src/vscp/common/win32helpers"
            "${VSCP_SUB}/src/vscp/daemon"
    )
endif()

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
        vscp_common
        vscp_sqlite3
)

if(TARGET EXPAT::EXPAT)
    target_link_libraries(vscpd PRIVATE EXPAT::EXPAT)
else()
    target_link_libraries(vscpd PRIVATE expat)
endif()

if(TARGET ZLIB::ZLIB)
    target_link_libraries(vscpd PRIVATE ZLIB::ZLIB)
else()
    target_link_libraries(vscpd PRIVATE z)
endif()

target_link_libraries(vscpd
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
)

# Platform-specific extra libs
if(UNIX AND NOT APPLE)
    target_link_libraries(vscpd PRIVATE m dl rt)
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
include(GNUInstallDirs)

install(TARGETS vscpd
    RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# Configuration file
if(WIN32)
    install(FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/install_files/windows/vscpd64.conf_windows_distro"
        DESTINATION "etc/vscp"
        RENAME vscpd.conf
    )
else()
    install(FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/install_files/unix/vscpd.json"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/vscp"
    )
    install(FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/install_files/unix/mimetypes.xml"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/vscp"
    )
endif()

# Man pages (Linux/macOS only)
if(UNIX)
    install(FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/man/vscpd.8"
        "${CMAKE_CURRENT_SOURCE_DIR}/man/uvscpd.8"
        DESTINATION "${CMAKE_INSTALL_MANDIR}/man8"
    )
    install(FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/man/vscp-mkpasswd.1"
        "${CMAKE_CURRENT_SOURCE_DIR}/man/vscpcmd.1"
        DESTINATION "${CMAKE_INSTALL_MANDIR}/man1"
    )
    install(FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/man/vscp.7"
        "${CMAKE_CURRENT_SOURCE_DIR}/man/vscpd-tls.7"
        "${CMAKE_CURRENT_SOURCE_DIR}/man/vscpdrivers.7"
        DESTINATION "${CMAKE_INSTALL_MANDIR}/man7"
    )
    install(FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/man/vscpd.conf.5"
        DESTINATION "${CMAKE_INSTALL_MANDIR}/man5"
    )
endif()

# systemd unit file (Linux only)
if(UNIX AND NOT APPLE)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/service/systemd/vscpd.service.simple")
        install(FILES
            "${CMAKE_CURRENT_SOURCE_DIR}/service/systemd/vscpd.service.simple"
            DESTINATION "${CMAKE_INSTALL_LIBDIR}/systemd/system"
            RENAME vscpd.service
        )
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/service/systemd/vscpd.service.notify")
        install(FILES
            "${CMAKE_CURRENT_SOURCE_DIR}/service/systemd/vscpd.service.notify"
            DESTINATION "${CMAKE_INSTALL_LIBDIR}/systemd/system"
            RENAME vscpd.service
        )
    endif()
endif()

# ---- CPack packaging ----
set(CPACK_PACKAGE_NAME             "vscp-tcpip-daemon")
set(CPACK_PACKAGE_VENDOR           "The VSCP project")
set(CPACK_PACKAGE_CONTACT          "info@vscp.org")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_DESCRIPTION
    "The VSCP TCP/IP Daemon (vscpd) is the main control centre for the VSCP
(Very Simple Control Protocol) framework. It provides a TCP/IP interface
for connected clients and drivers.")
set(CPACK_PACKAGE_VERSION          "${PROJECT_VERSION}")
set(CPACK_PACKAGE_VERSION_MAJOR    "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR    "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH    "${PROJECT_VERSION_PATCH}")
set(CPACK_PACKAGE_HOMEPAGE_URL     "https://www.vscp.org")
set(CPACK_RESOURCE_FILE_LICENSE    "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README     "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_STRIP_FILES              ON)

# ---- TGZ / ZIP (universal source-archive fallbacks) ----
set(CPACK_SOURCE_IGNORE_FILES
    "/.git/"
    "/build.*/"
    "/\\\\.cache/"
    "\\\\.swp$"
)

# ---- DEB (Linux) ----
set(CPACK_DEBIAN_PACKAGE_SECTION      "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY     "optional")
set(CPACK_DEBIAN_PACKAGE_DEPENDS
    "libssl3 | libssl1.1, libexpat1, libmosquitto1, zlib1g")
set(CPACK_DEBIAN_PACKAGE_SUGGESTS     "mosquitto")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER   "${CPACK_PACKAGE_CONTACT}")
set(CPACK_DEBIAN_FILE_NAME            DEB-DEFAULT)
set(CPACK_DEB_COMPONENT_INSTALL       OFF)

# ---- RPM (Linux) ----
set(CPACK_RPM_PACKAGE_GROUP           "Applications/System")
set(CPACK_RPM_PACKAGE_LICENSE         "MIT")
set(CPACK_RPM_PACKAGE_REQUIRES        "openssl-libs, expat, mosquitto, zlib")
set(CPACK_RPM_PACKAGE_URL             "${CPACK_PACKAGE_HOMEPAGE_URL}")
set(CPACK_RPM_FILE_NAME               RPM-DEFAULT)

# ---- NSIS (Windows installer) ----
set(CPACK_NSIS_DISPLAY_NAME           "VSCP TCP/IP Daemon ${PROJECT_VERSION}")
set(CPACK_NSIS_PACKAGE_NAME           "VSCP TCP/IP Daemon")
set(CPACK_NSIS_HELP_LINK              "https://docs.vscp.org/vscpd/")
set(CPACK_NSIS_URL_INFO_ABOUT         "${CPACK_PACKAGE_HOMEPAGE_URL}")
set(CPACK_NSIS_CONTACT                "${CPACK_PACKAGE_CONTACT}")
set(CPACK_NSIS_MODIFY_PATH            ON)
set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL ON)

# ---- Generator selection ----
if(WIN32)
    set(CPACK_GENERATOR "NSIS;ZIP")
elseif(APPLE)
    # productbuild / drag-drop archive; Homebrew formula is a separate file
    set(CPACK_GENERATOR "TGZ")
else()
    set(CPACK_GENERATOR "DEB;RPM;TGZ")
endif()

include(CPack)

# ---- Tests (optional) ----
if(VSCPD_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
