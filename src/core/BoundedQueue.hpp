#pragma once

#include "core/CancellationToken.hpp"

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace sectoryn {

// A first-in, first-out queue with a fixed capacity, shared by producer and consumer threads.
// A full queue makes producers wait or fail instead of growing, so queuing a large batch cannot
// exhaust memory. After close(), pushes fail and consumers drain what is left.
template <typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(std::size_t capacity)
        : capacity_(capacity) {
        if (capacity == 0) {
            throw std::invalid_argument("BoundedQueue capacity must be at least 1");
        }
    }

    BoundedQueue(const BoundedQueue&) = delete;
    BoundedQueue& operator=(const BoundedQueue&) = delete;
    BoundedQueue(BoundedQueue&&) = delete;
    BoundedQueue& operator=(BoundedQueue&&) = delete;
    ~BoundedQueue() = default;

    // Adds `item` if there is room. The item is moved from only when this returns true.
    [[nodiscard]] bool tryPush(T&& item) {
        {
            const std::lock_guard lock(mutex_);
            if (closed_ || items_.size() >= capacity_) {
                return false;
            }
            items_.push_back(std::move(item));
        }
        notEmpty_.notify_one();
        return true;
    }

    // Waits for room. Returns false, leaving `item` untouched, if the queue is closed or `token`
    // is cancelled first.
    [[nodiscard]] bool push(T&& item, const CancellationToken& token = {}) {
        {
            std::unique_lock lock(mutex_);
            const bool ready = notFull_.wait(
                lock, token, [this] { return closed_ || items_.size() < capacity_; });
            if (!ready || closed_) {
                return false;
            }
            items_.push_back(std::move(item));
        }
        notEmpty_.notify_one();
        return true;
    }

    [[nodiscard]] std::optional<T> tryPop() {
        std::optional<T> item;
        {
            const std::lock_guard lock(mutex_);
            if (items_.empty()) {
                return std::nullopt;
            }
            item.emplace(std::move(items_.front()));
            items_.pop_front();
        }
        notFull_.notify_one();
        return item;
    }

    // Waits for an item. Returns nothing once the queue is closed and empty, or if `token` is
    // cancelled first.
    [[nodiscard]] std::optional<T> pop(const CancellationToken& token = {}) {
        std::optional<T> item;
        {
            std::unique_lock lock(mutex_);
            const bool ready =
                notEmpty_.wait(lock, token, [this] { return closed_ || !items_.empty(); });
            if (!ready || items_.empty()) {
                return std::nullopt;
            }
            item.emplace(std::move(items_.front()));
            items_.pop_front();
        }
        notFull_.notify_one();
        return item;
    }

    // Refuses further pushes and wakes every waiting thread. Queued items can still be popped.
    void close() {
        {
            const std::lock_guard lock(mutex_);
            closed_ = true;
        }
        notEmpty_.notify_all();
        notFull_.notify_all();
    }

    // Removes and returns everything queued, e.g. to report pending jobs as cancelled.
    [[nodiscard]] std::vector<T> takeAll() {
        std::vector<T> taken;
        {
            const std::lock_guard lock(mutex_);
            taken.reserve(items_.size());
            for (T& item : items_) {
                taken.push_back(std::move(item));
            }
            items_.clear();
        }
        notFull_.notify_all();
        return taken;
    }

    [[nodiscard]] std::size_t size() const {
        const std::lock_guard lock(mutex_);
        return items_.size();
    }

    [[nodiscard]] bool closed() const {
        const std::lock_guard lock(mutex_);
        return closed_;
    }

    [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }

private:
    const std::size_t capacity_;
    mutable std::mutex mutex_;
    std::condition_variable_any notEmpty_;
    std::condition_variable_any notFull_;
    std::deque<T> items_;
    bool closed_ = false;
};

} // namespace sectoryn
