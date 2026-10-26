#pragma once

#include "engine/AnalysisResult.hpp"
#include "reports/ReportCommon.hpp"

#include <nlohmann/json.hpp>

#include <string>

namespace sectoryn {

// Raised when a field is removed or changes meaning. Added fields keep the version.
inline constexpr int kJsonReportSchemaVersion = 1;

// Keys keep a fixed order, so equal inputs serialize identically.
[[nodiscard]] nlohmann::ordered_json buildJsonReport(const AnalysisResult& result,
                                                     const ReportOptions& options = {});

// Indented by two spaces, with a final newline. Bytes that are not valid UTF-8 are written as
// U+FFFD rather than making the document unreadable.
[[nodiscard]] std::string renderJsonReport(const AnalysisResult& result,
                                           const ReportOptions& options = {});

} // namespace sectoryn
