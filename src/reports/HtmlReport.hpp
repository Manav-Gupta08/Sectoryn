#pragma once

#include "engine/AnalysisResult.hpp"
#include "reports/ReportCommon.hpp"

#include <string>
#include <string_view>

namespace sectoryn {

// A single self-contained HTML document with inline styles, no scripts and no external
// references. All text taken from the file is escaped, and the document's Content Security
// Policy blocks scripts and remote loads as a second line of defense.
[[nodiscard]] std::string renderHtmlReport(const AnalysisResult& result,
                                           const ReportOptions& options = {});

// The stylesheet embedded in every report.
[[nodiscard]] std::string_view htmlReportStyleSheet() noexcept;

} // namespace sectoryn
