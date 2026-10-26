#pragma once

#include "analysis/FileIdentifier.hpp"
#include "analysis/FileIntake.hpp"
#include "analysis/IndicatorClassifier.hpp"
#include "analysis/SectionAnalyzer.hpp"
#include "analysis/StringExtractor.hpp"
#include "detectors/Finding.hpp"
#include "detectors/RiskScorer.hpp"
#include "parsers/FieldStatus.hpp"
#include "parsers/PeModel.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace sectoryn {

struct ReportOptions {
    // Extracted strings can run to many megabytes. Indicators found in them are always included.
    bool includeStrings = false;
    // A full path can reveal user and folder names; by default only the file name is written.
    bool includeFilePath = false;
    // Start and finish times differ on every run. Without them, reports of the same file by the
    // same version are identical byte for byte.
    bool includeRunTimes = true;
};

// The file name, or the full path if the options allow it, as UTF-8.
[[nodiscard]] std::string reportedFileName(const FileMetadata& file, const ReportOptions& options);
[[nodiscard]] std::string reportedPath(const std::filesystem::path& path,
                                       const ReportOptions& options);

// ISO 8601 in UTC with millisecond precision, e.g. "2026-10-27T14:03:12.415Z".
[[nodiscard]] std::string formatUtc(std::chrono::system_clock::time_point time);

// COFF timestamps as a UTC date when they look like one. Linkers that build reproducibly store
// a hash in this field instead, so implausible values are labelled rather than converted.
[[nodiscard]] std::string formatCoffTimestamp(std::uint32_t seconds);

// Stable identifiers for report consumers. Unlike the display text from toString(), these never
// change once released.
[[nodiscard]] std::string_view reportToken(FieldState state) noexcept;
[[nodiscard]] std::string_view reportToken(TriageOutcome outcome) noexcept;
[[nodiscard]] std::string_view reportToken(Severity severity) noexcept;
[[nodiscard]] std::string_view reportToken(Confidence confidence) noexcept;
[[nodiscard]] std::string_view reportToken(FileKind kind) noexcept;
[[nodiscard]] std::string_view reportToken(PeFormat format) noexcept;
[[nodiscard]] std::string_view reportToken(SectionDataAvailability availability) noexcept;
[[nodiscard]] std::string_view reportToken(SectionAnomalyKind kind) noexcept;
[[nodiscard]] std::string_view reportToken(IndicatorKind kind) noexcept;
[[nodiscard]] std::string_view reportToken(StringEncoding encoding) noexcept;

} // namespace sectoryn
