#pragma once

#include "reputation/IReputationProvider.hpp"

#include <chrono>
#include <cstddef>
#include <deque>
#include <optional>

namespace sectoryn {

// Allows at most `maxRequests` requests in any window of the given length, matching the quotas
// that public reputation APIs impose. Not thread-safe.
class RateLimiter {
public:
    using Clock = std::chrono::steady_clock;

    RateLimiter(std::size_t maxRequests, std::chrono::seconds window);

    // Zero when a request may be sent now, otherwise how long to wait.
    [[nodiscard]] std::chrono::milliseconds delayBeforeNext(Clock::time_point now);
    void record(Clock::time_point now);

private:
    void forget(Clock::time_point now);

    std::size_t maxRequests_;
    std::chrono::seconds window_;
    std::deque<Clock::time_point> sent_;
};

// Retries requests that failed for transient reasons, a bounded number of times.
struct RetryPolicy {
    int maxAttempts = 3;
    std::chrono::milliseconds initialDelay{2000};
    std::chrono::milliseconds maxDelay{30000};

    // The delay before attempt `attempt + 1`, or nothing when the response is final or the
    // attempts are used up. `attempt` counts from 1.
    [[nodiscard]] std::optional<std::chrono::milliseconds>
    nextDelay(int attempt, const HttpResponse& response) const;
};

// Network failures, rate limiting and server errors may succeed when repeated.
[[nodiscard]] bool isTransient(const HttpResponse& response) noexcept;

} // namespace sectoryn
