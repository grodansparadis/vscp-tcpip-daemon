# - Find expat
# Find the native expat includes and libraries
#
#  EXPAT_INCLUDE_DIR  - where to find expat.h, etc.
#  EXPAT_INCLUDE_DIRS - alias for EXPAT_INCLUDE_DIR
#  EXPAT_LIBRARIES    - List of libraries when using libexpat.
#  EXPAT_FOUND        - True if libexpat found.

if (NOT EXPAT_INCLUDE_DIR)
  find_path(EXPAT_INCLUDE_DIR expat.h
    PATHS
      ${CMAKE_PREFIX_PATH}
      # macOS / Homebrew
      /opt/homebrew
      /usr/local
    PATH_SUFFIXES include
  )
endif()

if (NOT EXPAT_LIBRARY)
  find_library(
    EXPAT_LIBRARY
    NAMES expat libexpat
    PATHS
      ${CMAKE_PREFIX_PATH}
      # macOS / Homebrew
      /opt/homebrew
      /usr/local
    PATH_SUFFIXES lib
  )
endif()

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(
  EXPAT DEFAULT_MSG
  EXPAT_LIBRARY EXPAT_INCLUDE_DIR)

message(STATUS "libexpat include dir: ${EXPAT_INCLUDE_DIR}")
message(STATUS "libexpat: ${EXPAT_LIBRARY}")
set(EXPAT_LIBRARIES ${EXPAT_LIBRARY})
set(EXPAT_INCLUDE_DIRS ${EXPAT_INCLUDE_DIR})

mark_as_advanced(EXPAT_INCLUDE_DIR EXPAT_LIBRARY)
