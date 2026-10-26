#pragma once

#include "core/Result.hpp"
#include "detectors/RiskScorer.hpp"
#include "engine/AnalysisResult.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace sectoryn {

struct HistoryEntry {
    std::string sha256{};
    // Only the name: full paths can reveal user and folder names and are never stored.
    std::string fileName{};
    std::uint64_t sizeBytes = 0;
    TriageOutcome outcome = TriageOutcome::AnalysisIncomplete;
    double score = 0.0;
    std::size_t findings = 0;
    std::chrono::system_clock::time_point analyzedAt{};
    std::string engineVersion{};
};

[[nodiscard]] HistoryEntry historyEntryFor(const AnalysisResult& result);

struct RetentionPolicy {
    std::size_t maxEntries = 1000;
    std::chrono::days maxAge{90};
};

// Remembers, across sessions, which file contents were analyzed before and with what outcome.
// Only summaries are kept, never results or paths. Each change is saved atomically. Not
// thread-safe.
class HistoryStore {
public:
    // Files larger than this are refused rather than parsed.
    static constexpr std::size_t kMaxFileBytes = 16 * 1024 * 1024;

    // An empty history that will be saved to `file`.
    explicit HistoryStore(std::filesystem::path file, RetentionPolicy policy = {});

    // A missing file yields an empty history. Entries that fail validation are dropped; a file
    // that is not a history at all is an error.
    [[nodiscard]] static Result<HistoryStore>
    load(std::filesystem::path file, RetentionPolicy policy = {},
         std::chrono::system_clock::time_point now = std::chrono::system_clock::now());

    // Adds the entry, replacing any older one for the same content, applies the retention
    // policy and saves. The entry stays in memory even if saving fails.
    [[nodiscard]] Status record(HistoryEntry entry, std::chrono::system_clock::time_point now =
                                                        std::chrono::system_clock::now());

    [[nodiscard]] const HistoryEntry* find(std::string_view sha256) const;
    // Newest first.
    [[nodiscard]] const std::vector<HistoryEntry>& entries() const noexcept { return entries_; }

    [[nodiscard]] Status clear();

private:
    void prune(std::chrono::system_clock::time_point now);
    [[nodiscard]] Status save() const;

    std::filesystem::path file_;
    RetentionPolicy policy_;
    std::vector<HistoryEntry> entries_;
};

} // namespace sectoryn
