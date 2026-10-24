#include "core/CancellationToken.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <thread>

namespace sectoryn {
namespace {

TEST(Cancellation, DefaultTokenIsNeverCancelled) {
    const CancellationToken token;
    EXPECT_FALSE(token.stop_possible());
    EXPECT_TRUE(checkCancelled(token).hasValue());
}

TEST(Cancellation, RequestIsVisibleThroughToken) {
    CancellationSource source;
    const CancellationToken token = source.get_token();
    EXPECT_TRUE(checkCancelled(token).hasValue());

    EXPECT_TRUE(source.request_stop());
    const Status status = checkCancelled(token);
    ASSERT_FALSE(status.hasValue());
    EXPECT_EQ(status.error().code, ErrorCode::Cancelled);

    EXPECT_FALSE(source.request_stop());
}

TEST(Cancellation, CallbackRunsOnRequest) {
    CancellationSource source;
    bool notified = false;
    const std::stop_callback callback(source.get_token(), [&notified] { notified = true; });
    EXPECT_FALSE(notified);
    source.request_stop();
    EXPECT_TRUE(notified);
}

TEST(Cancellation, StopsWorkerThread) {
    std::atomic<bool> started = false;
    std::atomic<bool> observedCancel = false;

    std::jthread worker([&](const std::stop_token& token) {
        started = true;
        started.notify_one();
        // Block until cancellation arrives instead of polling.
        std::atomic<bool> stopRequested = false;
        const std::stop_callback wake(token, [&stopRequested] {
            stopRequested = true;
            stopRequested.notify_one();
        });
        stopRequested.wait(false);
        observedCancel = !checkCancelled(token).hasValue();
    });

    started.wait(false);
    worker.request_stop();
    worker.join();
    EXPECT_TRUE(observedCancel);
}

} // namespace
} // namespace sectoryn
