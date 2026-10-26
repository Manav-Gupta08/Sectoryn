#pragma once

#include "core/Result.hpp"
#include "core/WorkerPool.hpp"
#include "engine/AnalysisEngine.hpp"
#include "engine/Deduplicator.hpp"

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <unordered_map>

namespace sectoryn {

using JobId = std::uint64_t;

enum class JobState : std::uint8_t { Queued, Running, Completed, Duplicate, Failed, Cancelled };

[[nodiscard]] std::string_view toString(JobState state) noexcept;
[[nodiscard]] bool isFinal(JobState state) noexcept;

struct JobUpdate {
    JobId id = 0;
    std::filesystem::path path{};
    JobState state = JobState::Queued;
    // Set when the state is Completed.
    std::shared_ptr<const AnalysisResult> result{};
    // SHA-256 of the content, once it has been hashed.
    std::string sha256{};
    // Set when the state is Duplicate: the job that analyzes the same content.
    std::optional<JobId> duplicateOf{};
    // Why a job failed or was cancelled.
    std::string message{};
};

struct BatchOptions {
    std::size_t workerCount = 2;
    // Jobs waiting for a worker. Submitting beyond this is refused rather than buffered.
    std::size_t maxQueuedJobs = 256;
};

// Analyzes many files in parallel on a fixed number of threads. Each file is hashed first, and
// a file whose content another job in the batch already covers is reported as a duplicate
// instead of being analyzed again.
class BatchManager {
public:
    // Called on worker threads, and on the submitting thread for Queued, in the order the
    // states occur for each job. It must be thread-safe and must not call back into the manager.
    using UpdateCallback = std::function<void(const JobUpdate&)>;

    [[nodiscard]] static Result<std::unique_ptr<BatchManager>>
    create(std::shared_ptr<const AnalysisEngine> engine, BatchOptions options,
           UpdateCallback onUpdate);

    // Cancels all jobs and waits for the workers. Updates may still be delivered meanwhile.
    ~BatchManager();

    BatchManager(const BatchManager&) = delete;
    BatchManager& operator=(const BatchManager&) = delete;
    BatchManager(BatchManager&&) = delete;
    BatchManager& operator=(BatchManager&&) = delete;

    // Fails with ResourceLimitExceeded when maxQueuedJobs jobs are already waiting.
    [[nodiscard]] Result<JobId> submit(const std::filesystem::path& path);

    // Returns false if the job has already finished or does not exist.
    bool cancel(JobId id);
    void cancelAll();

    // Blocks until every submitted job has reached a final state.
    void waitForIdle();

    [[nodiscard]] std::size_t activeCount() const;
    [[nodiscard]] const BatchOptions& options() const noexcept { return options_; }

private:
    struct Job {
        JobId id = 0;
        std::filesystem::path path;
        std::stop_source stop;
    };

    BatchManager(std::shared_ptr<const AnalysisEngine> engine, BatchOptions options,
                 UpdateCallback onUpdate);

    void run(const std::shared_ptr<Job>& job);
    [[nodiscard]] JobUpdate analyze(const Job& job);
    void finish(const Job& job, const JobUpdate& update);

    std::shared_ptr<const AnalysisEngine> engine_;
    BatchOptions options_;
    UpdateCallback onUpdate_;
    Deduplicator deduplicator_;

    mutable std::mutex mutex_;
    std::condition_variable idle_;
    std::unordered_map<JobId, std::shared_ptr<Job>> active_;
    JobId nextId_ = 1;

    // Declared last so its threads stop before anything they use is destroyed.
    std::unique_ptr<WorkerPool> pool_;
};

} // namespace sectoryn
