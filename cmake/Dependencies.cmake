include(FetchContent)

# LIEF parses PE files. An installed LIEF 0.17 is used when CMake can find one; otherwise the
# pinned release is downloaded and built with only the PE/COFF modules enabled.
set(LIEF_PE ON CACHE BOOL "" FORCE)
set(LIEF_COFF ON CACHE BOOL "" FORCE)
set(LIEF_ELF OFF CACHE BOOL "" FORCE)
set(LIEF_MACHO OFF CACHE BOOL "" FORCE)
set(LIEF_DEX OFF CACHE BOOL "" FORCE)
set(LIEF_ART OFF CACHE BOOL "" FORCE)
set(LIEF_C_API OFF CACHE BOOL "" FORCE)
set(LIEF_PYTHON_API OFF CACHE BOOL "" FORCE)
set(LIEF_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LIEF_TESTS OFF CACHE BOOL "" FORCE)
set(LIEF_USE_MELKOR OFF CACHE BOOL "" FORCE)
set(LIEF_USE_CCACHE OFF CACHE BOOL "" FORCE)
set(LIEF_ENABLE_JSON OFF CACHE BOOL "" FORCE)
set(LIEF_INSTALL OFF CACHE BOOL "" FORCE)
# Parser diagnostics are reported through Sectoryn's own results, not printed to the console.
set(LIEF_LOGGING OFF CACHE BOOL "" FORCE)
set(LIEF_LOGGING_DEBUG OFF CACHE BOOL "" FORCE)

FetchContent_Declare(LIEF
  URL https://github.com/lief-project/LIEF/archive/refs/tags/0.17.6.tar.gz
  URL_HASH SHA256=5fbbd19c85912d417eabbaef2b98e70144496356964685b82e0792d708b9be87
  DOWNLOAD_EXTRACT_TIMESTAMP ON
  SYSTEM
  FIND_PACKAGE_ARGS 0.17 CONFIG)

FetchContent_MakeAvailable(LIEF)

# LIEF links Winsock (needed by its bundled Mbed TLS) only for shared builds.
if(WIN32 AND TARGET LIB_LIEF AND NOT BUILD_SHARED_LIBS)
  target_link_libraries(LIB_LIEF INTERFACE ws2_32)
endif()

# With debug info the static Debug library is about 1 GB, and every test executable that links
# it needs several GB of RAM. Sectoryn's own code keeps its debug info.
if(TARGET LIB_LIEF AND NOT MSVC)
  target_compile_options(LIB_LIEF PRIVATE -g0)
endif()

if(NOT TARGET LIEF::LIEF)
  message(FATAL_ERROR "LIEF was configured but did not provide the LIEF::LIEF target")
endif()

# JSON for rule catalogues and reports. Header-only and packaged by every supported platform.
find_package(nlohmann_json 3.11 REQUIRED CONFIG)

# YARA is optional: without libyara the YARA checks are unavailable and everything else works.
option(SECTORYN_WITH_YARA "Enable YARA scanning when libyara 4.3 or newer is installed" ON)
if(SECTORYN_WITH_YARA AND EXISTS "${CMAKE_CURRENT_LIST_DIR}/FindYara.cmake")
  find_package(Yara 4.3)
endif()
