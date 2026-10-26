# Finds libyara and provides the imported target Yara::yara.
#
# Result variables: Yara_FOUND, Yara_VERSION, Yara_INCLUDE_DIR, Yara_LIBRARY.
# Set Yara_ROOT to search a non-system installation first.

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(PC_Yara QUIET yara)
endif()

find_path(Yara_INCLUDE_DIR
  NAMES yara.h
  HINTS ${PC_Yara_INCLUDEDIR} ${PC_Yara_INCLUDE_DIRS})
find_library(Yara_LIBRARY
  NAMES yara libyara
  HINTS ${PC_Yara_LIBDIR} ${PC_Yara_LIBRARY_DIRS})

if(Yara_INCLUDE_DIR AND EXISTS "${Yara_INCLUDE_DIR}/yara/libyara.h")
  file(STRINGS "${Yara_INCLUDE_DIR}/yara/libyara.h" version_lines
    REGEX "^#define YR_(MAJOR|MINOR|MICRO)_VERSION +[0-9]+")
  foreach(part IN ITEMS MAJOR MINOR MICRO)
    string(REGEX REPLACE ".*#define YR_${part}_VERSION +([0-9]+).*" "\\1" Yara_${part}
      "${version_lines}")
  endforeach()
  set(Yara_VERSION "${Yara_MAJOR}.${Yara_MINOR}.${Yara_MICRO}")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Yara
  REQUIRED_VARS Yara_LIBRARY Yara_INCLUDE_DIR
  VERSION_VAR Yara_VERSION)

if(Yara_FOUND AND NOT TARGET Yara::yara)
  add_library(Yara::yara UNKNOWN IMPORTED)
  set_target_properties(Yara::yara PROPERTIES
    IMPORTED_LOCATION "${Yara_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${Yara_INCLUDE_DIR}")

  # A static libyara brings its own dependencies, which its pkg-config file lists.
  get_filename_component(yara_extension "${Yara_LIBRARY}" LAST_EXT)
  if(yara_extension STREQUAL CMAKE_STATIC_LIBRARY_SUFFIX)
    set(yara_dependencies ${PC_Yara_STATIC_LIBRARIES})
    list(REMOVE_ITEM yara_dependencies yara)
    if(NOT yara_dependencies)
      find_package(OpenSSL QUIET COMPONENTS Crypto)
      find_package(Threads REQUIRED)
      set(yara_dependencies Threads::Threads)
      if(OpenSSL_FOUND)
        list(APPEND yara_dependencies OpenSSL::Crypto)
      endif()
      if(NOT WIN32)
        list(APPEND yara_dependencies m)
      endif()
    endif()
    set_property(TARGET Yara::yara PROPERTY INTERFACE_LINK_LIBRARIES ${yara_dependencies})
  endif()
endif()

mark_as_advanced(Yara_INCLUDE_DIR Yara_LIBRARY)
