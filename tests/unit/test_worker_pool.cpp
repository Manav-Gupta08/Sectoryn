#include "core/WorkerPool.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <future>
#include <latch>
#include <mutex>
#include <set>
#include <stdexcept>
#include <thread>

namespace sectoryn {
namespace {

// Holds a pool's threads busy until released, so tests control what is queued.
class Gate {
public:
    void wait() { opened_.wait(); }
    void open() { opened_.count_down(); }

private:
    std::latch opened_{1};
};

TEST(WorkerPool, RejectsInvalidSizes) {
    EXPECT_THROW(WorkerPool(0, 1), std::invalid_argument);
    EXPECT_THROW(WorkerPool(1, 0), std::invalid_argument);
}

TEST(WorkerPool, RunsTasksOnSeveralThreads) {
    constexpr int kTasks = 200;
    std::atomic<int> done = 0;
    std::mutex mutex;
    std::set<std::thread::id> threads;
    {
        WorkerPool pool(4, kTasks);
        EXPECT_EQ(pool.threadCount(), 4U);
        for (int i = 0; i < kTasks; ++i) {
            ASSERT_TRUE(pool.trySubmit([&] {
                std::this_thread::yield();
                const std::lock_guard lock(mutex);
                threads.insert(std::this_thread::get_id());
                ++done;
            }));
        }
        pool.finish();
    }
    EXPECT_EQ(done.load(), kTasks);
    EXPECT_FALSE(threads.contains(std::this_thread::get_id()));
}

TEST(WorkerPool, RefusesWorkWhenQueueIsFull) {
    Gate gate;
    std::latch started(1);
    WorkerPool pool(1, 2);
    ASSERT_TRUE(pool.trySubmit([&] {
        started.count_down();
        gate.wait();
    }));
    started.wait();

    ASSERT_TRUE(pool.trySubmit([] {}));
    ASSERT_TRUE(pool.trySubmit([] {}));
    WorkerPool::Task extra = [] {};
    EXPECT_FALSE(pool.trySubmit(std::move(extra)));
    // NOLINTNEXTLINE(bugprone-use-after-move): a refused task must not be consumed
    EXPECT_TRUE(static_cast<bool>(extra)) << "a refused task must stay with the caller";
    EXPECT_EQ(pool.pendingCount(), 2U);
    gate.open();
}

TEST(WorkerPool, RefusesEmptyTasks) {
    WorkerPool pool(1, 1);
    EXPECT_FALSE(pool.trySubmit(WorkerPool::Task{}));
}

TEST(WorkerPool, TakePendingReturnsTasksThatDidNotStart) {
    Gate gate;
    std::latch started(1);
    std::atomic<int> ran = 0;
    WorkerPool pool(1, 4);
    ASSERT_TRUE(pool.trySubmit([&] {
        started.count_down();
        gate.wait();
    }));
    started.wait();
    for (int i = 0; i < 3; ++i) {
        ASSERT_TRUE(pool.trySubmit([&] { ++ran; }));
    }

    EXPECT_EQ(pool.takePending().size(), 3U);
    gate.open();
    pool.finish();
    EXPECT_EQ(ran.load(), 0);
}

TEST(WorkerPool, FinishRunsQueuedTasksAndRefusesNewOnes) {
    std::atomic<int> ran = 0;
    WorkerPool pool(2, 8);
    for (int i = 0; i < 8; ++i) {
        ASSERT_TRUE(pool.trySubmit([&] { ++ran; }));
    }
    pool.finish();
    EXPECT_EQ(ran.load(), 8);
    EXPECT_FALSE(pool.trySubmit([] {}));
}

TEST(WorkerPool, SurvivesThrowingTasks) {
    std::promise<void> after;
    WorkerPool pool(1, 4);
    ASSERT_TRUE(pool.trySubmit([] { throw std::runtime_error("task failed"); }));
    ASSERT_TRUE(pool.trySubmit([&] { after.set_value(); }));
    after.get_future().wait();
    pool.finish();
    EXPECT_EQ(pool.failedTaskCount(), 1U);
}

TEST(WorkerPool, DestructorDiscardsQueuedTasks) {
    Gate gate;
    std::latch started(1);
    std::atomic<int> ran = 0;
    std::jthread opener;
    {
        WorkerPool pool(1, 4);
        ASSERT_TRUE(pool.trySubmit([&] {
            started.count_down();
            gate.wait();
        }));
        started.wait();
        ASSERT_TRUE(pool.trySubmit([&] { ++ran; }));
        // Released only once the destructor has emptied the queue.
        opener = std::jthread([&] {
            while (pool.pendingCount() > 0) {
                std::this_thread::yield();
            }
            gate.open();
        });
    }
    EXPECT_EQ(ran.load(), 0);
}

} // namespace
} // namespace sectoryn
