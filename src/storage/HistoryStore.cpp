#include "storage/HistoryStore.hpp"

#include "reports/ReportCommon.hpp"
#include "utilities/FileIo.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cmath>
#include <optional>
#include <system_error>
#include <utility>

namespace sectoryn {

namespace {

using Json = nlohmann::ordered_json;
using Clock = std::chrono::system_clock;

constexpr std::string_view kSchema = "sectoryn-history";
constexpr int kSchemaVersion = 1;

constexpr std::array kOutcomes = {
    TriageOutcome::NoSignificantIndicators, TriageOutcome::SuspiciousIndicators,
    TriageOutcome::HighPriority,            TriageOutcome::AnalysisIncomplete,
    TriageOutcome::UnsupportedOrInvalid,
};

std::optional<TriageOutcome> parseOutcome(std::string_view token) {
    for (const TriageOutcome outcome : kOutcomes) {
        if (reportToken(outcome) == token) {
            return outcome;
        }
    }
    return std::nullopt;
}

bool isSha256(std::string_view text) {
    return text.size() == 64 && text.find_first_not_of("0123456789abcdef") == std::string::npos;
}

const std::string* stringField(const Json& object, const char* key) {
    const auto it = object.find(key);
    return it != object.end() && it->is_string() ? &it->get_ref<const std::string&>() : nullptr;
}

std::optional<HistoryEntry> parseEntry(const Json& item) {
    if (!item.is_object()) {
        return std::nullopt;
    }
    const std::string* sha256 = stringField(item, "sha256");
    const std::string* fileName = stringField(item, "file_name");
    const std::string* outcome = stringField(item, "outcome");
    const std::string* engineVersion = stringField(item, "engine_version");
    const auto size = item.find("size");
    const auto score = item.find("score");
    const auto findings = item.find("findings");
    const auto analyzedAt = item.find("analyzed_at_ms");
    if (sha256 == nullptr || !isSha256(*sha256) || fileName == nullptr || outcome == nullptr ||
        engineVersion == nullptr || size == item.end() || !size->is_number_unsigned() ||
        score == item.end() || !score->is_number() || findings == item.end() ||
        !findings->is_number_unsigned() || analyzedAt == item.end() ||
        !analyzedAt->is_number_integer()) {
        return std::nullopt;
    }
    const std::optional<TriageOutcome> parsedOutcome = parseOutcome(*outcome);
    const auto points = score->get<double>();
    if (!parsedOutcome || !std::isfinite(points) || points < 0.0 ||
        points > RiskAssessment::kMaxScore) {
        return std::nullopt;
    }
    HistoryEntry entry;
    entry.sha256 = *sha256;
    entry.fileName = *fileName;
    entry.sizeBytes = size->get<std::uint64_t>();
    entry.outcome = *parsedOutcome;
    entry.score = points;
    entry.findings = findings->get<std::size_t>();
    entry.analyzedAt =
        Clock::time_point(std::chrono::milliseconds(analyzedAt->get<std::int64_t>()));
    entry.engineVersion = *engineVersion;
    return entry;
}

Json toJson(const HistoryEntry& entry) {
    Json json;
    json["sha256"] = entry.sha256;
    json["file_name"] = entry.fileName;
    json["size"] = entry.sizeBytes;
    json["outcome"] = reportToken(entry.outcome);
    json["score"] = entry.score;
    json["findings"] = entry.findings;
    json["analyzed_at_ms"] =
        std::chrono::duration_cast<std::chrono::milliseconds>(entry.analyzedAt.time_since_epoch())
            .count();
    json["engine_version"] = entry.engineVersion;
    return json;
}

bool newerFirst(const HistoryEntry& a, const HistoryEntry& b) {
    return a.analyzedAt > b.analyzedAt;
}

} // namespace

HistoryEntry historyEntryFor(const AnalysisResult& result) {
    HistoryEntry entry;
    entry.sha256 = result.sha256;
    entry.fileName = reportedFileName(result.file, ReportOptions{});
    entry.sizeBytes = result.file.sizeBytes;
    entry.outcome = result.risk.outcome;
    entry.score = result.risk.score;
    entry.findings = result.findings.size();
    entry.analyzedAt = result.run.finished;
    entry.engineVersion = result.engine.version;
    return entry;
}

HistoryStore::HistoryStore(std::filesystem::path file, RetentionPolicy policy)
    : file_(std::move(file))
    , policy_(policy) {}

Result<HistoryStore> HistoryStore::load(std::filesystem::path file, RetentionPolicy policy,
                                        Clock::time_point now) {
    HistoryStore store(std::move(file), policy);
    std::error_code error;
    if (!std::filesystem::exists(store.file_, error)) {
        return store;
    }
    Result<std::string> text = readSmallFile(store.file_, kMaxFileBytes);
    if (!text) {
        return std::move(text).error();
    }
    const Json json = Json::parse(text.value(), nullptr, false);
    const std::string* schema = json.is_object() ? stringField(json, "schema") : nullptr;
    if (schema == nullptr || *schema != kSchema || !json.contains("entries") ||
        !json["entries"].is_array()) {
        return Error{ErrorCode::MalformedData, "the file is not a Sectoryn history"};
    }
    if (const auto version = json.find("schema_version");
        version == json.end() || !version->is_number_integer() ||
        version->get<int>() != kSchemaVersion) {
        return Error{ErrorCode::UnsupportedFormat, "the history was written by another version"};
    }
    for (const Json& item : json["entries"]) {
        if (std::optional<HistoryEntry> entry = parseEntry(item);
            entry && store.find(entry->sha256) == nullptr) {
            store.entries_.push_back(std::move(*entry));
        }
    }
    std::ranges::stable_sort(store.entries_, newerFirst);
    store.prune(now);
    return store;
}

Status HistoryStore::record(HistoryEntry entry, Clock::time_point now) {
    if (!isSha256(entry.sha256)) {
        return Error{ErrorCode::InvalidInput, "history entries need a SHA-256"};
    }
    std::erase_if(entries_, [&entry](const HistoryEntry& existing) {
        return existing.sha256 == entry.sha256;
    });
    const auto position = std::ranges::upper_bound(entries_, entry, newerFirst);
    entries_.insert(position, std::move(entry));
    prune(now);
    return save();
}

const HistoryEntry* HistoryStore::find(std::string_view sha256) const {
    const auto it = std::ranges::find(entries_, sha256, &HistoryEntry::sha256);
    return it == entries_.end() ? nullptr : &*it;
}

Status HistoryStore::clear() {
    entries_.clear();
    return save();
}

void HistoryStore::prune(Clock::time_point now) {
    const Clock::time_point cutoff = now - policy_.maxAge;
    std::erase_if(entries_, [cutoff](const HistoryEntry& entry) {
        return entry.analyzedAt < cutoff;
    });
    if (entries_.size() > policy_.maxEntries) {
        entries_.resize(policy_.maxEntries);
    }
}

Status HistoryStore::save() const {
    Json entries = Json::array();
    for (const HistoryEntry& entry : entries_) {
        entries.push_back(toJson(entry));
    }
    Json json;
    json["schema"] = kSchema;
    json["schema_version"] = kSchemaVersion;
    json["entries"] = std::move(entries);
    std::string text = json.dump(2, ' ', false, Json::error_handler_t::replace);
    text += '\n';

    std::error_code error;
    if (const auto directory = file_.parent_path(); !directory.empty()) {
        std::filesystem::create_directories(directory, error);
    }
    if (error) {
        return Error{ErrorCode::IoFailure, "cannot create the history directory"};
    }
    return writeFileAtomically(file_, text);
}

} // namespace sectoryn
