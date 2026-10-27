find_package(Qt6 6.4 REQUIRED COMPONENTS Widgets)

qt_add_executable(sectoryn WIN32
  main.cpp
  Application.hpp
  Application.cpp)

set_target_properties(sectoryn PROPERTIES
  AUTOMOC ON
  OUTPUT_NAME "sectoryn")

target_compile_definitions(sectoryn PRIVATE
  SECTORYN_VERSION="${PROJECT_VERSION}"
  QT_NO_KEYWORDS
  QT_NO_CAST_FROM_ASCII)

target_link_libraries(sectoryn PRIVATE sectoryn_core sectoryn_ui Qt6::Widgets)

sectoryn_set_warnings(sectoryn)

install(TARGETS sectoryn RUNTIME DESTINATION bin)
