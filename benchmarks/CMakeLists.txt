# Benchmarks reuse the synthetic PE builder from the tests so no binary samples are needed.
add_executable(sectoryn_bench
  bench_analysis.cpp
  "${PROJECT_SOURCE_DIR}/tests/support/PeBuilder.cpp"
  "${PROJECT_SOURCE_DIR}/tests/support/TempDir.cpp")
target_include_directories(sectoryn_bench PRIVATE "${PROJECT_SOURCE_DIR}/tests")
target_link_libraries(sectoryn_bench PRIVATE sectoryn_engine sectoryn_utilities)
sectoryn_set_warnings(sectoryn_bench)
