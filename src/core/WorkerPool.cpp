#include "core/WorkerPool.hpp"

#include <stdexcept>
#include <utility>

namespace sectoryn {

WorkerPool::WorkerPool(std::size_t threadCount, std::size_t queueCapacity)
    : queue_(queueCapacity) {
    if (threadCount == 0) {
        throw std::invalid_argument("WorkerPool needs at least one thread");
    }
    threads_.reserve(threadCount);
    try {
        for (std::size_t i = 0; i < threadCount; ++i) {
            threads_.emplace_back([this] { work(); });
        }
    } catch (...) {
        queue_.close();
        threads_.clear();
        throw;
    }
}

WorkerPool::~WorkerPool() {
    static_cast<void>(queue_.takeAll());
    finish();
}

bool WorkerPool::trySubmit(Task&& task) {
    return task && queue_.tryPush(std::move(task));
}

std::vector<WorkerPool::Task> WorkerPool::takePending() {
    return queue_.takeAll();
}

void WorkerPool::finish() {
    queue_.close();
    for (std::jthread& thread : threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
}

void WorkerPool::work() {
    while (std::optional<Task> task = queue_.pop()) {
        try {
            (*task)();
        } catch (...) {
            ++failedTasks_;
        }
    }
}

} // namespace sectoryn
