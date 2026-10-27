# Fuzz harnesses operate on byte buffers only; nothing is written to disk or executed.
# With Clang they link libFuzzer and the sanitizers. With other compilers each harness is built
# as a replay tool that runs the inputs named on its command line, which is how crashes found
# elsewhere are reproduced.
file(GLOB SECTORYN_FUZZ_HARNESSES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/fuzz_*.cpp")

foreach(harness IN LISTS SECTORYN_FUZZ_HARNESSES)
  get_filename_component(name "${harness}" NAME_WE)
  add_executable(${name} "${harness}")
  target_include_directories(${name} PRIVATE "${PROJECT_SOURCE_DIR}/src")
  target_link_libraries(${name} PRIVATE ${SECTORYN_TEST_LIBRARIES})
  sectoryn_set_warnings(${name})

  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined)
  else()
    target_sources(${name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/ReplayMain.cpp")
  endif()
endforeach()
