#include "engine/BatchManager.hpp"

#include "analysis/FileIntake.hpp"
#include "core/Config.hpp"
#include "utilities/Sha256.hpp"

#include <exception>
#include <format>
#include <utility>

namespace sectoryn {

namespace {

// Hashing reads the file once more than the analysis itself, but it lets a duplicate be
// recognized before the expensive work starts.
Result<std::string> hashFile(const std::filesystem::path& path, const AnalysisLimits& limits,
                             const CancellationToken& token) {
    Result<OpenedFile> opened = openForAnalysis(path, limits);
    if (!opened) {
        return std::move(opened).error();
    }
    Result<Sha256::Digest> digest =
        sha256File(opened.value().reader, limits.readChunkBytes, token);
    if (!digest) {
        return std::move(digest).error();
    }
    return Sha256::toHex(digest.value());
}

} // namespace

std::string_view toString(JobState state) noexcept {
    switch (state) {
    case JobState::Queued:
        return "Queued";
    case JobState::Running:
        return "Running";
    case JobState::Completed:
        return "Completed";
    case JobState::Duplicate:
        return "Duplicate";
    case JobState::Failed:
        return "Failed";
    case JobState::Cancelled:
        return "Cancelled";
    }
    return "Unknown";
}

bool isFinal(JobState state) noexcept {
    return state != JobState::Queued && state != JobState::Running;
}

Result<std::unique_ptr<BatchManager>> BatchManager::create(
    std::shared_ptr<const AnalysisEngine> engine, BatchOptions options, UpdateCallback onUpdate) {
    if (!engine) {
        return Error{ErrorCode::InvalidInput, "no analysis engine given"};
    }
    if (!onUpdate) {
        return Error{ErrorCode::InvalidInput, "no update callback given"};
    }
    if (options.workerCount == 0 || options.workerCount > Config::kMaxWorkerCount) {
        return Error{ErrorCode::InvalidInput,
                     std::format("worker count must be between 1 and {}", Config::kMaxWorkerCount)};
    }
    if (options.maxQueuedJobs == 0 || options.maxQueuedJobs > Config::kMaxQueuedJobsCeiling) {
        return Error{ErrorCode::InvalidInput,
                     std::format("queued job limit must be between 1 and {}",
                                 Config::kMaxQueuedJobsCeiling)};
    }
    return std::unique_ptr<BatchManager>(
        new BatchManager(std::move(engine), options, std::move(onUpdate)));
}

BatchManager::BatchManager(std::shared_ptr<const AnalysisEngine> engine, BatchOptions options,
                           UpdateCallback onUpdate)
    : engine_(std::move(engine))
    , options_(options)
    , onUpdate_(std::move(onUpdate))
    , pool_(std::make_unique<WorkerPool>(options.workerCount, options.maxQueuedJobs)) {}

BatchManager::~BatchManager() {
    cancelAll();
    pool_->finish();
}

Result<JobId> BatchManager::submit(const std::filesystem::path& path) {
    const std::lock_guard lock(mutex_);
    // Only this function adds work, so a free slot seen here cannot be taken by anyone else.
    if (pool_->pendingCount() >= options_.maxQueuedJobs) {
        return Error{ErrorCode::ResourceLimitExceeded,
                     std::format("the batch queue already holds {} files", options_.maxQueuedJobs)};
    }

    auto job = std::make_shared<Job>();
    job->id = nextId_++;
    job->path = path;
    active_.emplace(job->id, job);
    // Reported before the task is queued, so Queued always precedes Running.
    onUpdate_({.id = job->id, .path = path, .state = JobState::Queued});

    if (!pool_->trySubmit([this, job] { run(job); })) {
        active_.erase(job->id);
        onUpdate_({.id = job->id,
                   .path = path,
                   .state = JobState::Cancelled,
                   .message = "the batch is shutting down"});
        return Error{ErrorCode::Cancelled, "the batch is shutting down"};
    }
    return job->id;
}

bool BatchManager::cancel(JobId id) {
    const std::lock_guard lock(mutex_);
    const auto it = active_.find(id);
    if (it == active_.end()) {
        return false;
    }
    it->second->stop.request_stop();
    return true;
}

void BatchManager::cancelAll() {
    const std::lock_guard lock(mutex_);
    for (const auto& [id, job] : active_) {
        job->stop.request_stop();
    }
}

void BatchManager::waitForIdle() {
    std::unique_lock lock(mutex_);
    idle_.wait(lock, [this] { return active_.empty(); });
}

std::size_t BatchManager::activeCount() const {
    const std::lock_guard lock(mutex_);
    return active_.size();
}

void BatchManager::run(const std::shared_ptr<Job>& job) {
    if (job->stop.stop_requested()) {
        finish(*job, {.id = job->id,
                      .path = job->path,
                      .state = JobState::Cancelled,
                      .message = "cancelled before it started"});
        return;
    }
    onUpdate_({.id = job->id, .path = job->path, .state = JobState::Running});

    JobUpdate update;
    try {
        update = analyze(*job);
    } catch (const std::exception& e) {
        update = {.id = job->id,
                  .path = job->path,
                  .state = JobState::Failed,
                  .message = std::format("analysis failed: {}", e.what())};
    }
    finish(*job, update);
}

JobUpdate BatchManager::analyze(const Job& job) {
    const CancellationToken token = job.stop.get_token();
    JobUpdate update{.id = job.id, .path = job.path};

    // A file that cannot be hashed is analyzed anyway; the engine then reports the real problem.
    const Result<std::string> sha256 = hashFile(job.path, engine_->options().limits, token);
    if (!sha256 && sha256.error().code == ErrorCode::Cancelled) {
        update.state = JobState::Cancelled;
        update.message = sha256.error().describe();
        return update;
    }
    if (sha256) {
        update.sha256 = sha256.value();
        if (const std::optional<JobId> owner = deduplicator_.claim(sha256.value(), job.id)) {
            update.state = JobState::Duplicate;
            update.duplicateOf = owner;
            update.message = std::format("same content as job {}", *owner);
            return update;
        }
    }

    Result<AnalysisResult> result = engine_->analyze(job.path, token);
    if (result) {
        update.state = JobState::Completed;
        update.sha256 = result.value().sha256;
        update.result = std::make_shared<const AnalysisResult>(std::move(result).value());
        return update;
    }
    const bool cancelled = result.error().code == ErrorCode::Cancelled;
    if (cancelled && sha256) {
        // Let a later copy of the same file be analyzed in its place.
        deduplicator_.release(sha256.value(), job.id);
    }
    update.state = cancelled ? JobState::Cancelled : JobState::Failed;
    update.message = result.error().describe();
    return update;
}

void BatchManager::finish(const Job& job, const JobUpdate& update) {
    onUpdate_(update);
    const std::lock_guard lock(mutex_);
    active_.erase(job.id);
    if (active_.empty()) {
        idle_.notify_all();
    }
}

} // namespace sectoryn
