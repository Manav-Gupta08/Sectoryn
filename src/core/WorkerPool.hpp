#pragma once

#include "core/BoundedQueue.hpp"

#include <atomic>
#include <cstddef>
#include <functional>
#include <thread>
#include <vector>

namespace sectoryn {

// Runs tasks on a fixed set of threads. Tasks wait in a bounded queue, and trySubmit() refuses
// work when it is full instead of letting the backlog grow without limit.
class WorkerPool {
public:
    using Task = std::function<void()>;

    // Both arguments must be at least 1.
    WorkerPool(std::size_t threadCount, std::size_t queueCapacity);
    // Discards queued tasks and waits for running ones. Tasks are not interrupted, so owners
    // should cancel their work first.
    ~WorkerPool();

    WorkerPool(const WorkerPool&) = delete;
    WorkerPool& operator=(const WorkerPool&) = delete;
    WorkerPool(WorkerPool&&) = delete;
    WorkerPool& operator=(WorkerPool&&) = delete;

    // The task is moved from only when this returns true.
    [[nodiscard]] bool trySubmit(Task&& task);

    // Removes tasks that have not started. They are returned so their owner can account for them.
    [[nodiscard]] std::vector<Task> takePending();

    // Stops accepting tasks, runs everything already queued, and waits for the threads to end.
    void finish();

    [[nodiscard]] std::size_t threadCount() const noexcept { return threads_.size(); }
    [[nodiscard]] std::size_t pendingCount() const { return queue_.size(); }
    // Tasks are expected not to throw. One that does is counted here and the thread carries on.
    [[nodiscard]] std::size_t failedTaskCount() const noexcept { return failedTasks_; }

private:
    void work();

    BoundedQueue<Task> queue_;
    std::atomic<std::size_t> failedTasks_ = 0;
    std::vector<std::jthread> threads_;
};

} // namespace sectoryn
