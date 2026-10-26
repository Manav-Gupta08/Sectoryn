#include "storage/HistoryStore.hpp"
#include "support/TempDir.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <string>

namespace sectoryn {
namespace {

using namespace std::chrono_literals;
using Clock = std::chrono::system_clock;

const Clock::time_point kNow = std::chrono::sys_days{std::chrono::year{2026} / 10 / 29};

HistoryEntry entry(char digit, Clock::time_point analyzedAt, std::string name = "sample.exe") {
    HistoryEntry result;
    result.sha256 = std::string(64, digit);
    result.fileName = std::move(name);
    result.sizeBytes = 4096;
    result.outcome = TriageOutcome::SuspiciousIndicators;
    result.score = 27.5;
    result.findings = 3;
    result.analyzedAt = analyzedAt;
    result.engineVersion = "0.1.0";
    return result;
}

TEST(HistoryStore, MissingFileMeansEmptyHistory) {
    const test::TempDir dir;
    const Result<HistoryStore> store = HistoryStore::load(dir.path() / "history.json");
    ASSERT_TRUE(store.hasValue()) << store.error().describe();
    EXPECT_TRUE(store.value().entries().empty());
}

TEST(HistoryStore, RecordsAndReloads) {
    const test::TempDir dir;
    const auto file = dir.path() / "nested" / "history.json";
    {
        HistoryStore store(file);
        ASSERT_TRUE(store.record(entry('a', kNow - 2h), kNow).hasValue());
        ASSERT_TRUE(store.record(entry('b', kNow - 1h, "other.dll"), kNow).hasValue());
    }
    const Result<HistoryStore> loaded = HistoryStore::load(file, {}, kNow);
    ASSERT_TRUE(loaded.hasValue()) << loaded.error().describe();
    const auto& entries = loaded.value().entries();
    ASSERT_EQ(entries.size(), 2U);
    EXPECT_EQ(entries[0].fileName, "other.dll") << "newest first";
    EXPECT_EQ(entries[1].sha256, std::string(64, 'a'));
    EXPECT_EQ(entries[1].outcome, TriageOutcome::SuspiciousIndicators);
    EXPECT_DOUBLE_EQ(entries[1].score, 27.5);
    EXPECT_EQ(entries[1].findings, 3U);
    EXPECT_EQ(entries[1].analyzedAt, kNow - 2h);
}

TEST(HistoryStore, KeepsOneEntryPerContent) {
    const test::TempDir dir;
    HistoryStore store(dir.path() / "history.json");
    ASSERT_TRUE(store.record(entry('a', kNow - 3h, "first.exe"), kNow).hasValue());
    ASSERT_TRUE(store.record(entry('a', kNow - 1h, "renamed.exe"), kNow).hasValue());
    ASSERT_EQ(store.entries().size(), 1U);
    EXPECT_EQ(store.find(std::string(64, 'a'))->fileName, "renamed.exe");
    EXPECT_EQ(store.find(std::string(64, 'f')), nullptr);
}

TEST(HistoryStore, AppliesRetentionPolicy) {
    const test::TempDir dir;
    const RetentionPolicy policy{.maxEntries = 2, .maxAge = std::chrono::days(7)};
    HistoryStore store(dir.path() / "history.json", policy);
    ASSERT_TRUE(store.record(entry('a', kNow - std::chrono::days(8)), kNow).hasValue());
    EXPECT_TRUE(store.entries().empty()) << "older than the maximum age";

    ASSERT_TRUE(store.record(entry('b', kNow - 3h), kNow).hasValue());
    ASSERT_TRUE(store.record(entry('c', kNow - 2h), kNow).hasValue());
    ASSERT_TRUE(store.record(entry('d', kNow - 1h), kNow).hasValue());
    ASSERT_EQ(store.entries().size(), 2U);
    EXPECT_EQ(store.find(std::string(64, 'b')), nullptr) << "the oldest entry goes first";
}

TEST(HistoryStore, RejectsEntriesWithoutHash) {
    const test::TempDir dir;
    HistoryStore store(dir.path() / "history.json");
    HistoryEntry bad = entry('a', kNow);
    bad.sha256 = "not a hash";
    EXPECT_FALSE(store.record(bad, kNow).hasValue());
    EXPECT_TRUE(store.entries().empty());
}

TEST(HistoryStore, RefusesFilesThatAreNotHistories) {
    const test::TempDir dir;
    for (const char* text : {"not json", "[]", R"({"schema": "other", "entries": []})",
                             R"({"schema": 5, "entries": []})"}) {
        const Result<HistoryStore> store = HistoryStore::load(dir.write("history.json", text));
        ASSERT_FALSE(store.hasValue()) << text;
        EXPECT_EQ(store.error().code, ErrorCode::MalformedData) << text;
    }
    const Result<HistoryStore> newer = HistoryStore::load(dir.write(
        "history.json", R"({"schema": "sectoryn-history", "schema_version": 2, "entries": []})"));
    ASSERT_FALSE(newer.hasValue());
    EXPECT_EQ(newer.error().code, ErrorCode::UnsupportedFormat);
}

TEST(HistoryStore, DropsInvalidEntriesAndKeepsTheRest) {
    const test::TempDir dir;
    const std::string valid = std::string(64, 'c');
    const std::string text = R"({"schema": "sectoryn-history", "schema_version": 1, "entries": [
        {"sha256": "short", "file_name": "a", "size": 1, "outcome": "high_priority",
         "score": 1, "findings": 0, "analyzed_at_ms": 0, "engine_version": "x"},
        {"sha256": ")" + valid + R"(", "file_name": "b", "size": 1, "outcome": "made_up",
         "score": 1, "findings": 0, "analyzed_at_ms": 0, "engine_version": "x"},
        {"sha256": ")" + valid + R"(", "file_name": "c", "size": -1, "outcome": "high_priority",
         "score": 1, "findings": 0, "analyzed_at_ms": 0, "engine_version": "x"},
        {"sha256": ")" + valid + R"(", "file_name": "d", "size": 1, "outcome": "high_priority",
         "score": 500, "findings": 0, "analyzed_at_ms": 0, "engine_version": "x"},
        "not an object",
        {"sha256": ")" + valid + R"(", "file_name": "good", "size": 1, "outcome": "high_priority",
         "score": 55, "findings": 2, "analyzed_at_ms": 1793232000000, "engine_version": "x"}
    ]})";
    const RetentionPolicy policy{.maxEntries = 10, .maxAge = std::chrono::days(36500)};
    const Result<HistoryStore> store =
        HistoryStore::load(dir.write("history.json", text), policy, kNow);
    ASSERT_TRUE(store.hasValue()) << store.error().describe();
    ASSERT_EQ(store.value().entries().size(), 1U);
    EXPECT_EQ(store.value().entries()[0].fileName, "good");
    EXPECT_EQ(store.value().entries()[0].outcome, TriageOutcome::HighPriority);
}

TEST(HistoryStore, RefusesOversizedFiles) {
    const test::TempDir dir;
    const std::string text(HistoryStore::kMaxFileBytes + 1, ' ');
    const Result<HistoryStore> store = HistoryStore::load(dir.write("history.json", text));
    ASSERT_FALSE(store.hasValue());
    EXPECT_EQ(store.error().code, ErrorCode::ResourceLimitExceeded);
}

TEST(HistoryStore, ClearRemovesEverything) {
    const test::TempDir dir;
    const auto file = dir.path() / "history.json";
    HistoryStore store(file);
    ASSERT_TRUE(store.record(entry('a', kNow), kNow).hasValue());
    ASSERT_TRUE(store.clear().hasValue());
    EXPECT_TRUE(HistoryStore::load(file, {}, kNow).value().entries().empty());
}

TEST(HistoryStore, EntryForResultKeepsOnlyTheFileName) {
    AnalysisResult result;
    result.file.path = std::filesystem::path("users") / "alice" / "sample.exe";
    result.sha256 = std::string(64, 'e');
    result.risk.outcome = TriageOutcome::HighPriority;
    result.risk.score = 60.0;
    result.run.finished = kNow;
    const HistoryEntry recorded = historyEntryFor(result);
    EXPECT_EQ(recorded.fileName, "sample.exe");
    EXPECT_EQ(recorded.analyzedAt, kNow);
    EXPECT_EQ(recorded.outcome, TriageOutcome::HighPriority);
}

} // namespace
} // namespace sectoryn
