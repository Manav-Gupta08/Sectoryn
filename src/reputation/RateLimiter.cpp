#include "reputation/RateLimiter.hpp"

#include <algorithm>

namespace sectoryn {

RateLimiter::RateLimiter(std::size_t maxRequests, std::chrono::seconds window)
    : maxRequests_(std::max<std::size_t>(maxRequests, 1))
    , window_(std::max(window, std::chrono::seconds{1})) {}

void RateLimiter::forget(Clock::time_point now) {
    while (!sent_.empty() && now - sent_.front() >= window_) {
        sent_.pop_front();
    }
}

std::chrono::milliseconds RateLimiter::delayBeforeNext(Clock::time_point now) {
    forget(now);
    if (sent_.size() < maxRequests_) {
        return std::chrono::milliseconds{0};
    }
    const auto wait = sent_.front() + window_ - now;
    return std::chrono::ceil<std::chrono::milliseconds>(wait);
}

void RateLimiter::record(Clock::time_point now) {
    forget(now);
    sent_.push_back(now);
    // Only the last maxRequests_ entries can ever matter.
    while (sent_.size() > maxRequests_) {
        sent_.pop_front();
    }
}

bool isTransient(const HttpResponse& response) noexcept {
    return response.status == 0 || response.status == 429 ||
           (response.status >= 500 && response.status <= 599);
}

std::optional<std::chrono::milliseconds>
RetryPolicy::nextDelay(int attempt, const HttpResponse& response) const {
    if (attempt < 1 || attempt >= maxAttempts || !isTransient(response)) {
        return std::nullopt;
    }
    std::chrono::milliseconds delay = initialDelay;
    for (int i = 1; i < attempt && delay < maxDelay; ++i) {
        delay *= 2;
    }
    if (response.retryAfter) {
        // A server asking for a longer pause than we are willing to wait gets no retry.
        if (*response.retryAfter > maxDelay) {
            return std::nullopt;
        }
        delay = std::max<std::chrono::milliseconds>(delay, *response.retryAfter);
    }
    return std::min(delay, maxDelay);
}

} // namespace sectoryn
