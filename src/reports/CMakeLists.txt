add_library(sectoryn_reports)
add_library(Sectoryn::reports ALIAS sectoryn_reports)

file(GLOB SECTORYN_REPORTS_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/*.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
target_sources(sectoryn_reports PRIVATE ${SECTORYN_REPORTS_SOURCES})

# HTML reports are single self-contained files, so the stylesheet is compiled in.
set(report_css "${PROJECT_SOURCE_DIR}/resources/report/report.css")
if(EXISTS "${report_css}")
  file(READ "${report_css}" SECTORYN_REPORT_CSS)
  set(generated "${CMAKE_CURRENT_BINARY_DIR}/ReportStyleData.cpp")
  file(CONFIGURE OUTPUT "${generated}" @ONLY CONTENT [=[
#include "reports/HtmlReport.hpp"

namespace sectoryn {

std::string_view htmlReportStyleSheet() noexcept {
    return R"sectoryn_css(@SECTORYN_REPORT_CSS@)sectoryn_css";
}

} // namespace sectoryn
]=])
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${report_css}")
  target_sources(sectoryn_reports PRIVATE "${generated}")
endif()

# The JSON report API returns nlohmann::ordered_json so batch exports can combine reports.
target_link_libraries(sectoryn_reports
  PUBLIC sectoryn_core sectoryn_engine nlohmann_json::nlohmann_json)
sectoryn_set_warnings(sectoryn_reports)
