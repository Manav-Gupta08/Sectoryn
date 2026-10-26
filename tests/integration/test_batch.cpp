#include "engine/BatchManager.hpp"
#include "engine/Deduplicator.hpp"
#include "support/PeBuilder.hpp"
#include "support/TempDir.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <format>
#include <latch>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace sectoryn {
namespace {

using test::bytesOf;
using test::PeBuilder;

std::shared_ptr<const AnalysisEngine> engine() {
    static const std::shared_ptr<const AnalysisEngine> instance = [] {
        Result<AnalysisEngine> created = AnalysisEngine::createDefault();
        EXPECT_TRUE(created.hasValue());
        return std::make_shared<const AnalysisEngine>(std::move(created).value());
    }();
    return instance;
}

std::vector<std::byte> uniquePe(int variant) {
    return PeBuilder()
        .addSection(".text", PeBuilder::kCode, bytesOf(std::string(0x200, '\x90')))
        .addSection(".rdata", PeBuilder::kReadOnly, bytesOf(std::format("variant {}", variant)))
        .build();
}

// Collects updates from worker threads. Optionally holds the first Running job inside the
// callback, which keeps a single worker busy while a test fills the queue behind it.
class Recorder {
public:
    explicit Recorder(bool holdFirstRunningJob = false)
        : hold_(holdFirstRunningJob) {}

    BatchManager::UpdateCallback callback() {
        return [this](const JobUpdate& update) {
            {
                const std::lock_guard lock(mutex_);
                updates_[update.id].push_back(update);
            }
            if (update.state == JobState::Running && hold_.exchange(false)) {
                running_.count_down();
                release_.wait();
            }
        };
    }

    void waitUntilHeld() { running_.wait(); }
    void release() { release_.count_down(); }

    std::vector<JobState> states(JobId id) const {
        const std::lock_guard lock(mutex_);
        std::vector<JobState> states;
        for (const JobUpdate& update : updates_.at(id)) {
            states.push_back(update.state);
        }
        return states;
    }

    JobUpdate last(JobId id) const {
        const std::lock_guard lock(mutex_);
        return updates_.at(id).back();
    }

private:
    std::atomic<bool> hold_;
    std::latch running_{1};
    std::latch release_{1};
    mutable std::mutex mutex_;
    std::map<JobId, std::vector<JobUpdate>> updates_;
};

std::unique_ptr<BatchManager> makeManager(Recorder& recorder, BatchOptions options = {}) {
    Result<std::unique_ptr<BatchManager>> manager =
        BatchManager::create(engine(), options, recorder.callback());
    EXPECT_TRUE(manager.hasValue()) << manager.error().describe();
    return std::move(manager).value();
}

TEST(Deduplicator, FirstClaimOwnsTheContent) {
    Deduplicator deduplicator;
    EXPECT_EQ(deduplicator.claim("aa", 1), std::nullopt);
    EXPECT_EQ(deduplicator.claim("aa", 1), std::nullopt) << "claiming again is harmless";
    EXPECT_EQ(deduplicator.claim("aa", 2), 1U);
    EXPECT_EQ(deduplicator.claim("bb", 2), std::nullopt);
    EXPECT_EQ(deduplicator.size(), 2U);
}

TEST(Deduplicator, OnlyTheOwnerCanRelease) {
    Deduplicator deduplicator;
    ASSERT_EQ(deduplicator.claim("aa", 1), std::nullopt);
    deduplicator.release("aa", 2);
    EXPECT_EQ(deduplicator.claim("aa", 3), 1U);
    deduplicator.release("aa", 1);
    EXPECT_EQ(deduplicator.claim("aa", 3), std::nullopt);
}

TEST(BatchManager, RejectsInvalidOptions) {
    Recorder recorder;
    EXPECT_FALSE(BatchManager::create(nullptr, {}, recorder.callback()).hasValue());
    EXPECT_FALSE(BatchManager::create(engine(), {}, {}).hasValue());
    EXPECT_FALSE(BatchManager::create(engine(), {.workerCount = 0}, recorder.callback())
                     .hasValue());
    EXPECT_FALSE(BatchManager::create(engine(), {.workerCount = 1, .maxQueuedJobs = 0},
                                      recorder.callback())
                     .hasValue());
}

TEST(BatchManager, AnalyzesEveryFile) {
    const test::TempDir dir;
    Recorder recorder;
    auto manager = makeManager(recorder, {.workerCount = 3, .maxQueuedJobs = 16});

    std::vector<JobId> ids;
    for (int i = 0; i < 6; ++i) {
        Result<JobId> id = manager->submit(dir.write(std::format("file{}.exe", i), uniquePe(i)));
        ASSERT_TRUE(id.hasValue()) << id.error().describe();
        ids.push_back(id.value());
    }
    manager->waitForIdle();
    EXPECT_EQ(manager->activeCount(), 0U);

    for (const JobId id : ids) {
        EXPECT_EQ(recorder.states(id),
                  (std::vector{JobState::Queued, JobState::Running, JobState::Completed}));
        const JobUpdate last = recorder.last(id);
        ASSERT_NE(last.result, nullptr);
        EXPECT_EQ(last.result->identification.kind, FileKind::Pe);
        EXPECT_EQ(last.result->file.path, last.path);
    }
}

TEST(BatchManager, AnalyzesIdenticalContentOnce) {
    const test::TempDir dir;
    Recorder recorder;
    auto manager = makeManager(recorder, {.workerCount = 2, .maxQueuedJobs = 8});
    const std::vector<std::byte> content = uniquePe(0);

    std::vector<JobId> ids;
    for (const char* name : {"a.exe", "b.exe", "c.dll"}) {
        ids.push_back(manager->submit(dir.write(name, content)).value());
    }
    manager->waitForIdle();

    std::vector<JobUpdate> completed;
    std::vector<JobUpdate> duplicates;
    for (const JobId id : ids) {
        const JobUpdate last = recorder.last(id);
        (last.state == JobState::Duplicate ? duplicates : completed).push_back(last);
    }
    ASSERT_EQ(completed.size(), 1U);
    ASSERT_EQ(duplicates.size(), 2U);
    EXPECT_EQ(completed.front().state, JobState::Completed);
    for (const JobUpdate& duplicate : duplicates) {
        EXPECT_EQ(duplicate.duplicateOf, completed.front().id);
        EXPECT_EQ(duplicate.result, nullptr);
    }
}

TEST(BatchManager, RefusesJobsBeyondTheQueueLimit) {
    const test::TempDir dir;
    Recorder recorder(true);
    auto manager = makeManager(recorder, {.workerCount = 1, .maxQueuedJobs = 2});

    ASSERT_TRUE(manager->submit(dir.write("0.exe", uniquePe(0))).hasValue());
    recorder.waitUntilHeld();
    ASSERT_TRUE(manager->submit(dir.write("1.exe", uniquePe(1))).hasValue());
    ASSERT_TRUE(manager->submit(dir.write("2.exe", uniquePe(2))).hasValue());

    const Result<JobId> refused = manager->submit(dir.write("3.exe", uniquePe(3)));
    ASSERT_FALSE(refused.hasValue());
    EXPECT_EQ(refused.error().code, ErrorCode::ResourceLimitExceeded);

    recorder.release();
    manager->waitForIdle();
}

TEST(BatchManager, CancelAllStopsRunningAndQueuedJobs) {
    const test::TempDir dir;
    Recorder recorder(true);
    auto manager = makeManager(recorder, {.workerCount = 1, .maxQueuedJobs = 8});

    std::vector<JobId> ids;
    ids.push_back(manager->submit(dir.write("0.exe", uniquePe(0))).value());
    recorder.waitUntilHeld();
    for (int i = 1; i < 4; ++i) {
        ids.push_back(manager->submit(dir.write(std::format("{}.exe", i), uniquePe(i))).value());
    }

    manager->cancelAll();
    recorder.release();
    manager->waitForIdle();

    for (const JobId id : ids) {
        EXPECT_EQ(recorder.last(id).state, JobState::Cancelled) << id;
    }
    EXPECT_EQ(recorder.states(ids[1]), (std::vector{JobState::Queued, JobState::Cancelled}));
}

TEST(BatchManager, CancelsOneJob) {
    const test::TempDir dir;
    Recorder recorder(true);
    auto manager = makeManager(recorder, {.workerCount = 1, .maxQueuedJobs = 8});

    const JobId first = manager->submit(dir.write("0.exe", uniquePe(0))).value();
    recorder.waitUntilHeld();
    const JobId second = manager->submit(dir.write("1.exe", uniquePe(1))).value();

    EXPECT_TRUE(manager->cancel(second));
    EXPECT_FALSE(manager->cancel(9999));
    recorder.release();
    manager->waitForIdle();

    EXPECT_EQ(recorder.last(first).state, JobState::Completed);
    EXPECT_EQ(recorder.last(second).state, JobState::Cancelled);
    EXPECT_FALSE(manager->cancel(first)) << "finished jobs cannot be cancelled";
}

TEST(BatchManager, ReportsFilesThatCannotBeRead) {
    const test::TempDir dir;
    Recorder recorder;
    auto manager = makeManager(recorder);

    const JobId id = manager->submit(dir.path() / "missing.exe").value();
    manager->waitForIdle();

    const JobUpdate last = recorder.last(id);
    EXPECT_EQ(last.state, JobState::Failed);
    EXPECT_FALSE(last.message.empty());
}

TEST(BatchManager, DestructionCancelsOutstandingWork) {
    const test::TempDir dir;
    Recorder recorder;
    std::vector<JobId> ids;
    {
        auto manager = makeManager(recorder, {.workerCount = 2, .maxQueuedJobs = 32});
        for (int i = 0; i < 20; ++i) {
            ids.push_back(
                manager->submit(dir.write(std::format("{}.exe", i), uniquePe(i))).value());
        }
    }
    for (const JobId id : ids) {
        EXPECT_TRUE(isFinal(recorder.last(id).state)) << id;
    }
}

} // namespace
} // namespace sectoryn
