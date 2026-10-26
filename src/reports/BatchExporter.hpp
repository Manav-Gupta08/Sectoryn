#pragma once

#include "core/Result.hpp"
#include "engine/AnalysisResult.hpp"
#include "engine/BatchManager.hpp"
#include "reports/ReportCommon.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace sectoryn {

// The outcome of one batch job, as listed in a batch summary.
struct BatchEntry {
    JobId id = 0;
    std::filesystem::path path{};
    JobState state = JobState::Queued;
    std::string sha256{};
    std::optional<TriageOutcome> outcome{};
    double score = 0.0;
    std::size_t findings = 0;
    std::optional<JobId> duplicateOf{};
    std::string message{};
};

// One row per job. Every cell is quoted, and cells that a spreadsheet would treat as a formula
// are prefixed with an apostrophe, so file names cannot inject formulas.
[[nodiscard]] std::string renderBatchCsv(std::span<const BatchEntry> entries,
                                         const ReportOptions& options = {});

[[nodiscard]] std::string renderBatchJson(std::span<const BatchEntry> entries,
                                          const ReportOptions& options = {});

enum class ReportFormat : std::uint8_t { Json, Html };

// Writes the reports for `result` into `directory`, named after the file's SHA-256 so that
// files with the same name from different folders cannot overwrite each other's reports.
[[nodiscard]] Result<std::vector<std::filesystem::path>>
writeReports(const std::filesystem::path& directory, const AnalysisResult& result,
             std::span<const ReportFormat> formats, const ReportOptions& options = {});

} // namespace sectoryn
