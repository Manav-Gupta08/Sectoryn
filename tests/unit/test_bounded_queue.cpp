#include "core/BoundedQueue.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>
#include <vector>

namespace sectoryn {
namespace {

using namespace std::chrono_literals;

TEST(BoundedQueue, RejectsZeroCapacity) {
    EXPECT_THROW(BoundedQueue<int>(0), std::invalid_argument);
}

TEST(BoundedQueue, IsFirstInFirstOut) {
    BoundedQueue<int> queue(4);
    for (int i = 1; i <= 3; ++i) {
        ASSERT_TRUE(queue.tryPush(int{i}));
    }
    EXPECT_EQ(queue.size(), 3U);
    EXPECT_EQ(queue.tryPop(), 1);
    EXPECT_EQ(queue.tryPop(), 2);
    EXPECT_EQ(queue.tryPop(), 3);
    EXPECT_EQ(queue.tryPop(), std::nullopt);
}

TEST(BoundedQueue, RefusesItemsBeyondCapacity) {
    BoundedQueue<std::unique_ptr<int>> queue(2);
    ASSERT_TRUE(queue.tryPush(std::make_unique<int>(1)));
    ASSERT_TRUE(queue.tryPush(std::make_unique<int>(2)));

    auto extra = std::make_unique<int>(3);
    EXPECT_FALSE(queue.tryPush(std::move(extra)));
    // NOLINTNEXTLINE(bugprone-use-after-move): a refused push must not consume the item
    ASSERT_NE(extra, nullptr) << "a refused item must stay with the caller";
    EXPECT_EQ(*extra, 3); // NOLINT(bugprone-use-after-move)
    EXPECT_EQ(queue.size(), 2U);
}

TEST(BoundedQueue, PushWaitsForRoom) {
    BoundedQueue<int> queue(1);
    ASSERT_TRUE(queue.tryPush(1));

    std::atomic<bool> pushed = false;
    std::jthread producer([&] {
        EXPECT_TRUE(queue.push(2));
        pushed = true;
    });
    std::this_thread::sleep_for(50ms);
    EXPECT_FALSE(pushed.load());

    EXPECT_EQ(queue.pop(), 1);
    producer.join();
    EXPECT_TRUE(pushed.load());
    EXPECT_EQ(queue.pop(), 2);
}

TEST(BoundedQueue, PopWaitsForItem) {
    BoundedQueue<int> queue(1);
    std::jthread producer([&] {
        std::this_thread::sleep_for(20ms);
        EXPECT_TRUE(queue.tryPush(7));
    });
    EXPECT_EQ(queue.pop(), 7);
}

TEST(BoundedQueue, CloseLetsConsumersDrainThenStop) {
    BoundedQueue<int> queue(4);
    ASSERT_TRUE(queue.tryPush(1));
    queue.close();

    EXPECT_TRUE(queue.closed());
    EXPECT_FALSE(queue.tryPush(2));
    EXPECT_FALSE(queue.push(3));
    EXPECT_EQ(queue.pop(), 1);
    EXPECT_EQ(queue.pop(), std::nullopt);
}

TEST(BoundedQueue, CloseWakesWaitingThreads) {
    BoundedQueue<int> empty(1);
    std::jthread consumer([&] { EXPECT_EQ(empty.pop(), std::nullopt); });

    BoundedQueue<int> full(1);
    ASSERT_TRUE(full.tryPush(1));
    std::jthread producer([&] { EXPECT_FALSE(full.push(2)); });

    std::this_thread::sleep_for(20ms);
    empty.close();
    full.close();
}

TEST(BoundedQueue, CancellationStopsWaiting) {
    BoundedQueue<int> queue(1);
    CancellationSource source;
    std::jthread consumer([&] { EXPECT_EQ(queue.pop(source.get_token()), std::nullopt); });
    std::this_thread::sleep_for(20ms);
    source.request_stop();
    consumer.join();

    ASSERT_TRUE(queue.tryPush(1));
    EXPECT_FALSE(queue.push(2, source.get_token()));
    EXPECT_EQ(queue.size(), 1U);
}

TEST(BoundedQueue, TakeAllEmptiesTheQueueAndFreesRoom) {
    BoundedQueue<int> queue(3);
    for (int i = 0; i < 3; ++i) {
        ASSERT_TRUE(queue.tryPush(int{i}));
    }
    EXPECT_EQ(queue.takeAll(), (std::vector<int>{0, 1, 2}));
    EXPECT_EQ(queue.size(), 0U);
    EXPECT_TRUE(queue.tryPush(9));
}

TEST(BoundedQueue, DeliversEveryItemOnceAcrossThreads) {
    constexpr int kProducers = 4;
    constexpr int kItemsEach = 2000;
    BoundedQueue<int> queue(16);
    std::atomic<long long> sum = 0;
    std::atomic<int> received = 0;

    std::vector<std::jthread> consumers;
    for (int c = 0; c < 3; ++c) {
        consumers.emplace_back([&] {
            while (const std::optional<int> item = queue.pop()) {
                sum += *item;
                ++received;
            }
        });
    }
    {
        std::vector<std::jthread> producers;
        for (int p = 0; p < kProducers; ++p) {
            producers.emplace_back([&queue, p] {
                for (int i = 0; i < kItemsEach; ++i) {
                    EXPECT_TRUE(queue.push(p * kItemsEach + i));
                }
            });
        }
    }
    queue.close();
    consumers.clear();

    constexpr int kTotal = kProducers * kItemsEach;
    EXPECT_EQ(received.load(), kTotal);
    EXPECT_EQ(sum.load(), static_cast<long long>(kTotal) * (kTotal - 1) / 2);
}

} // namespace
} // namespace sectoryn
