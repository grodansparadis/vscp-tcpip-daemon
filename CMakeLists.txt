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
# Copyright (C) 2000-2026 Ake Hedman and contributors, the VSCP project
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.16...3.31)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/src/version.h" VSCPD_VERSION_MAJOR REGEX "^#define VSCPD_VERSION_MAJOR[ \\t]+([0-9]+)$")
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/src/version.h" VSCPD_VERSION_MINOR REGEX "^#define VSCPD_VERSION_MINOR[ \\t]+([0-9]+)$")
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/src/version.h" VSCPD_VERSION_PATCH REGEX "^#define VSCPD_VERSION_PATCH[ \\t]+([0-9]+)$")
string(REGEX REPLACE "^#define VSCPD_VERSION_(MAJOR|MINOR|PATCH)[ \\t]+" "" VSCPD_VERSION_MAJOR "${VSCPD_VERSION_MAJOR}")
string(REGEX REPLACE "^#define VSCPD_VERSION_(MAJOR|MINOR|PATCH)[ \\t]+" "" VSCPD_VERSION_MINOR "${VSCPD_VERSION_MINOR}")
string(REGEX REPLACE "^#define VSCPD_VERSION_(MAJOR|MINOR|PATCH)[ \\t]+" "" VSCPD_VERSION_PATCH "${VSCPD_VERSION_PATCH}")

project(vscp-tcpip-daemon
    VERSION ${VSCPD_VERSION_MAJOR}.${VSCPD_VERSION_MINOR}.${VSCPD_VERSION_PATCH}
    DESCRIPTION "VSCP TCP/IP Daemon"
    LANGUAGES CXX C)

# ---- C standard ----
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ---- C++ standard ----
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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
# list(APPEND CMAKE_MODULE_PATH
#     "${CMAKE_CURRENT_SOURCE_DIR}/third-party/vscp/cmake/modules")

# ---- System libraries ----
include(GNUInstallDirs)

if(UNIX AND NOT APPLE)
    set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "Installation prefix" FORCE)
    set(CMAKE_INSTALL_SYSCONFDIR "/etc" CACHE PATH "System configuration directory" FORCE)
    set(CMAKE_INSTALL_LOCALSTATEDIR "/var" CACHE PATH "State directory" FORCE)
endif()

option(VSCPD_BUILD_MANPAGES "Build and install man pages" ON)
set(VSCPD_PACKAGE_GENERATORS "" CACHE STRING "Semicolon-separated list of CPack generators to enable")

if(DEFINED MQTTVSCPD_PACKAGE_GENERATORS AND NOT VSCPD_PACKAGE_GENERATORS)
    set(VSCPD_PACKAGE_GENERATORS "${VSCPD_PACKAGE_GENERATORS}")
endif()

set(VSCP_BUILD_TESTS OFF CACHE BOOL "Build VSCP library tests" FORCE)
set(VSCP_INSTALL OFF CACHE BOOL "Install VSCP helper libraries" FORCE)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(EXPAT REQUIRED)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
if(WIN32)
    find_package(unofficial-sodium CONFIG REQUIRED)
    find_package(dlfcn-win32 CONFIG REQUIRED)
    set(VSCPD_SODIUM_TARGET unofficial-sodium::sodium)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBSODIUM REQUIRED IMPORTED_TARGET libsodium)
    set(VSCPD_SODIUM_TARGET PkgConfig::LIBSODIUM)
endif()
# find_package(nlohmann_json 3.11.0 REQUIRED)
# find_package(spdlog 1.15 REQUIRED)


# if (NOT nlohmann_json_FOUND)
#     message(FATAL_ERROR "nlohmann_json not found, install the nlohmann-json development package")
# endif()


# if (NOT spdlog_FOUND)
#     message(FATAL_ERROR "spdlog not found, install the libspdlog development package")
# endif()


include(FetchContent)

FetchContent_Declare(
  vscp
  GIT_REPOSITORY https://github.com/grodansparadis/vscp.git
  GIT_TAG c3d4b22ceb1abfc12a16d6f19549645df71227b6
)
FetchContent_MakeAvailable(vscp)

# FetchContent_Declare(
#   vscp_firmware
#   GIT_REPOSITORY https://github.com/grodansparadis/vscp-firmware.git
#   GIT_TAG v1.7.0
# )
# FetchContent_MakeAvailable(vscp_firmware)

FetchContent_Declare(
    mongoose
    GIT_REPOSITORY https://github.com/cesanta/mongoose.git
    GIT_TAG 7.23
)
FetchContent_MakeAvailable(mongoose)

FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.17.0
)
FetchContent_MakeAvailable(spdlog)

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.12.0
)
FetchContent_MakeAvailable(nlohmann_json)


if(NOT TARGET SQLite3::SQLite3) # CMake < 4.3
  add_library(SQLite3::SQLite3 ALIAS SQLite::SQLite3)
endif()

# ---- Convenience alias for the submodule source root ----
#set(vscp_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third-party/vscp")

# Use a platform-appropriate daemon entrypoint.
# if(WIN32)
#     set(VSCPD_MAIN_SOURCE "${vscp_SOURCE_DIR}/src/vscp/vscpd.cpp")
# else()
#     set(VSCPD_MAIN_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/src/vscpd.cpp")
# endif()

# ---- Daemon source files ----
# Build the daemon using vscp submodule for common functionality.
set(VSCPD_SOURCES
    "${VSCPD_MAIN_SOURCE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/vscpd.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/controlobject.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/tcpipsrv.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/interfacelist.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/userlist.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/devicethread.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/devicelist.cpp"    
    "${CMAKE_CURRENT_SOURCE_DIR}/src/clientlist.cpp" 
    "${vscp_SOURCE_DIR}/src/vscp/common/guid.cpp"
    "${vscp_SOURCE_DIR}/src/vscp/common/vscphelper.cpp"
    "${vscp_SOURCE_DIR}/src/vscp/common/vscpdatetime.cpp"
    "${vscp_SOURCE_DIR}/src/vscp/common/vscp-guid-parser.c"
    "${vscp_SOURCE_DIR}/src/common/vscphelper-common.cpp"
    "${vscp_SOURCE_DIR}/src/common/crc.c"
    "${vscp_SOURCE_DIR}/src/common/crc8.c"
    "${vscp_SOURCE_DIR}/src/common/vscp-aes.c"
    "${vscp_SOURCE_DIR}/src/common/vscpmd5.c"
    "${vscp_SOURCE_DIR}/src/common/vscpbase64.c"
    "${vscp_SOURCE_DIR}/src/common/randpassword.cpp"
    "${vscp_SOURCE_DIR}/src/common/sockettcp.c"
    "${mongoose_SOURCE_DIR}/mongoose.c"
)

if(WIN32)
    list(APPEND VSCPD_SOURCES
        "${CMAKE_CURRENT_SOURCE_DIR}/src/win32helpers/getopt.c"
    )
endif()

# ---- Build the vscpd executable ----
add_executable(vscpd ${VSCPD_SOURCES})
set_target_properties(vscpd PROPERTIES OUTPUT_NAME "vscpd")

# ---- Build the password-hash utility ----
add_executable(mk_password_hash
    "${CMAKE_CURRENT_SOURCE_DIR}/src/mkpasswd/mk_password_hash.cpp"
)
target_link_libraries(mk_password_hash PRIVATE ${VSCPD_SODIUM_TARGET})

# The daemon headers and third-party imports live under src/daemon.
target_include_directories(vscpd
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${vscp_SOURCE_DIR}/src/common/"
        "${vscp_SOURCE_DIR}/src/vscp/common/"
        "${EXPAT_INCLUDE_DIRS}"
        "${MOSQUITTO_INCLUDE_DIRS}"
        "${CURL_INCLUDE_DIRS}"
        "${mongoose_SOURCE_DIR}/"
        "${spdlog_SOURCE_DIR}/include/"
        "${nlohmann_json_SOURCE_DIR}/include/"
        "${mongoose_SOURCE_DIR}/"
)

if(WIN32)
    target_compile_definitions(vscpd
        PRIVATE
            WIN32_LEAN_AND_MEAN
    )

    target_include_directories(vscpd
        PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src/win32helpers"
            "${vscp_SOURCE_DIR}/src/vscp/common/win32helpers"
            "${vscp_SOURCE_DIR}/src/common"
            "${vscp_SOURCE_DIR}/src/vscp/common"
            "${EXPAT_INCLUDE_DIRS}"
            "${MOSQUITTO_INCLUDE_DIRS}"
            "${CURL_INCLUDE_DIRS}"
            "${mongoose_SOURCE_DIR}"  
            "${spdlog_SOURCE_DIR}/include"
            "${nlohmann_json_SOURCE_DIR}/include"
    )
endif()

target_compile_definitions(vscpd PRIVATE
    USE_IPV6
    USE_WEBSOCKET
    USE_SERVER_STATS
)

target_link_libraries(vscpd
    PRIVATE
        Threads::Threads
        SQLite3::SQLite3
        spdlog
        nlohmann_json
        ${VSCPD_SODIUM_TARGET}
        ${EXPAT_LIBRARIES}
        ${CURL_LIBRARIES}
)

if(WIN32)
    find_package(Threads REQUIRED)
    find_package(PThreads4W CONFIG QUIET)
    if(NOT TARGET PThreads4W::PThreads4W_CXXEXC AND NOT TARGET PThreads4W::PThreads4W)
        find_package(pthread CONFIG QUIET)
    endif()

    if(TARGET PThreads4W::PThreads4W_CXXEXC)
        target_link_libraries(vscpd PRIVATE PThreads4W::PThreads4W_CXXEXC)
    elseif(TARGET PThreads4W::PThreads4W)
        target_link_libraries(vscpd PRIVATE PThreads4W::PThreads4W)
    elseif(TARGET Threads::Threads)
        target_link_libraries(vscpd PRIVATE Threads::Threads)
    elseif(MSVC)
        message(FATAL_ERROR "No usable pthreads target found for MSVC. Install the PThreads4W/pthread dependency (for example via vcpkg) before building.")
    endif()

    target_link_libraries(vscpd PRIVATE netapi32)
    target_link_libraries(vscpd PRIVATE dlfcn-win32::dl)

    if(MSVC)
        target_compile_options(vscpd PRIVATE /utf-8)
    endif()

    target_compile_definitions(vscpd
        PRIVATE
            _CRT_SECURE_NO_WARNINGS
            _WINSOCK_DEPRECATED_NO_WARNINGS
            WIN32_LEAN_AND_MEAN
            NOMINMAX)
endif()

if(UNIX AND NOT APPLE)
    find_path(SYSTEMD_INCLUDE_DIR systemd/sd-daemon.h)
    find_library(SYSTEMD_LIBRARY NAMES systemd)
    if(NOT SYSTEMD_INCLUDE_DIR OR NOT SYSTEMD_LIBRARY)
        message(FATAL_ERROR "libsystemd headers and library are required to build mqttvscpd on Linux.")
    endif()

    target_include_directories(vscpd PRIVATE ${SYSTEMD_INCLUDE_DIR})
    target_link_libraries(vscpd PRIVATE ${SYSTEMD_LIBRARY})
endif()

if(VSCPD_BUILD_MANPAGES AND UNIX)
    add_subdirectory(man)
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

# Clang on macOS treats -Wnon-pod-varargs as an error for code in
# third-party/vscp/src/vscp/common/tcpipsrv.cpp that passes std::string
# through a variadic function.  Suppress the warning for that file only.
if(APPLE)
    set_source_files_properties(
        "${vscp_SOURCE_DIR}/src/vscp/common/tcpipsrv.cpp"
        PROPERTIES COMPILE_OPTIONS "-Wno-non-pod-varargs"
    )
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
        "${CMAKE_CURRENT_SOURCE_DIR}/install/windows/vscpd64.conf_windows_distro"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/vscp"
        RENAME vscpd.conf
    )
else()
    install(FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/install/unix/vscpd.json"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/vscp"
    )
    install(FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/install/unix/mimetypes.xml"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/vscp"
    )
    install(PROGRAMS
        "${CMAKE_CURRENT_SOURCE_DIR}/install/unix/tcpip-vscpd.init"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/init.d"
        RENAME vscpd
    )
endif()

# Man pages (Linux/macOS only)
if(UNIX)
    install(FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/man/vscpd.8"
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
set(CPACK_PACKAGE_VERSION          "${VSCPD_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MAJOR    "${VSCPD_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR    "${VSCPD_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH    "${VSCPD_VERSION_PATCH}")
set(CPACK_PACKAGE_HOMEPAGE_URL     "https://www.vscp.org")
set(CPACK_RESOURCE_FILE_LICENSE    "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README     "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_STRIP_FILES              ON)

if(UNIX AND NOT APPLE)
    set(CPACK_SET_DESTDIR ON)
endif()

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
    "libssl3 | libssl1.1")
set(CPACK_DEBIAN_PACKAGE_SUGGESTS     "mosquitto")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER   "${CPACK_PACKAGE_CONTACT}")
set(CPACK_DEBIAN_FILE_NAME            DEB-DEFAULT)
set(CPACK_DEB_COMPONENT_INSTALL       OFF)

# ---- RPM (Linux) ----
set(CPACK_RPM_PACKAGE_GROUP           "Applications/System")
set(CPACK_RPM_PACKAGE_LICENSE         "MIT")
set(CPACK_RPM_PACKAGE_REQUIRES        "openssl-libs")
set(CPACK_RPM_PACKAGE_URL             "${CPACK_PACKAGE_HOMEPAGE_URL}")
set(CPACK_RPM_FILE_NAME               RPM-DEFAULT)

# ---- NSIS (Windows installer) ----
set(CPACK_NSIS_DISPLAY_NAME           "VSCP TCP/IP Daemon ${VSCPD_VERSION_MAJOR}.${VSCPD_VERSION_MINOR}.${VSCPD_VERSION_PATCH}")
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
