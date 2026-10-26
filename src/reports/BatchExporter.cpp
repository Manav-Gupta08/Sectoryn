#include "reports/BatchExporter.hpp"

#include "reports/HtmlReport.hpp"
#include "reports/JsonReport.hpp"
#include "utilities/FileIo.hpp"

#include <nlohmann/json.hpp>

#include <format>
#include <initializer_list>
#include <string_view>

namespace sectoryn {

namespace {

constexpr int kBatchSchemaVersion = 1;

std::string_view stateToken(JobState state) noexcept {
    switch (state) {
    case JobState::Queued:
        return "queued";
    case JobState::Running:
        return "running";
    case JobState::Completed:
        return "completed";
    case JobState::Duplicate:
        return "duplicate";
    case JobState::Failed:
        return "failed";
    case JobState::Cancelled:
        return "cancelled";
    }
    return "unknown";
}

bool isScored(const BatchEntry& entry) {
    return entry.outcome && *entry.outcome != TriageOutcome::UnsupportedOrInvalid;
}

void appendCsvCell(std::string& out, std::string_view value) {
    out += '"';
    if (!value.empty() && std::string_view("=+-@\t\r").find(value.front()) != std::string::npos) {
        out += '\'';
    }
    for (const char c : value) {
        if (c == '"') {
            out += '"';
        }
        out += c;
    }
    out += '"';
}

void appendCsvRow(std::string& out, std::initializer_list<std::string_view> cells) {
    bool first = true;
    for (const std::string_view cell : cells) {
        if (!first) {
            out += ',';
        }
        first = false;
        appendCsvCell(out, cell);
    }
    out += "\r\n";
}

} // namespace

std::string renderBatchCsv(std::span<const BatchEntry> entries, const ReportOptions& options) {
    std::string out;
    appendCsvRow(out, {"job", "file", "state", "sha256", "outcome", "score", "findings",
                       "duplicate_of", "message"});
    for (const BatchEntry& entry : entries) {
        appendCsvRow(
            out, {std::to_string(entry.id), reportedPath(entry.path, options),
                  stateToken(entry.state), entry.sha256,
                  entry.outcome ? reportToken(*entry.outcome) : std::string_view{},
                  isScored(entry) ? std::format("{:.1f}", entry.score) : std::string(),
                  entry.outcome ? std::to_string(entry.findings) : std::string(),
                  entry.duplicateOf ? std::to_string(*entry.duplicateOf) : std::string(),
                  entry.message});
    }
    return out;
}

std::string renderBatchJson(std::span<const BatchEntry> entries, const ReportOptions& options) {
    using Json = nlohmann::ordered_json;
    Json jobs = Json::array();
    for (const BatchEntry& entry : entries) {
        Json job;
        job["id"] = entry.id;
        job["file"] = reportedPath(entry.path, options);
        job["state"] = stateToken(entry.state);
        job["sha256"] = entry.sha256.empty() ? Json(nullptr) : Json(entry.sha256);
        job["outcome"] = entry.outcome ? Json(reportToken(*entry.outcome)) : Json(nullptr);
        job["score"] = isScored(entry) ? Json(entry.score) : Json(nullptr);
        job["findings"] = entry.outcome ? Json(entry.findings) : Json(nullptr);
        job["duplicate_of"] = entry.duplicateOf ? Json(*entry.duplicateOf) : Json(nullptr);
        job["message"] = entry.message;
        jobs.push_back(std::move(job));
    }
    Json json;
    json["schema"] = "sectoryn-batch";
    json["schema_version"] = kBatchSchemaVersion;
    json["jobs"] = std::move(jobs);
    std::string text = json.dump(2, ' ', false, Json::error_handler_t::replace);
    text += '\n';
    return text;
}

Result<std::vector<std::filesystem::path>>
writeReports(const std::filesystem::path& directory, const AnalysisResult& result,
             std::span<const ReportFormat> formats, const ReportOptions& options) {
    // The hash names the files, so it must be exactly what the engine produces.
    if (result.sha256.size() != 64 ||
        result.sha256.find_first_not_of("0123456789abcdef") != std::string::npos) {
        return Error{ErrorCode::InvalidInput, "the result has no valid SHA-256"};
    }
    std::vector<std::filesystem::path> written;
    for (const ReportFormat format : formats) {
        const bool html = format == ReportFormat::Html;
        const std::filesystem::path path =
            directory / (result.sha256 + (html ? ".report.html" : ".report.json"));
        const std::string contents =
            html ? renderHtmlReport(result, options) : renderJsonReport(result, options);
        if (Status status = writeFileAtomically(path, contents); !status) {
            return std::move(status).error();
        }
        written.push_back(path);
    }
    return written;
}

} // namespace sectoryn
