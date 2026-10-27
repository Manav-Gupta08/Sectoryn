#pragma once

#include "reputation/IReputationProvider.hpp"

#include <chrono>
#include <cstddef>
#include <list>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace sectoryn {

// Remembers recent lookups so that revisiting a file does not contact the service again.
// Holds at most `capacity` reports; the least recently used one is dropped first. Not
// thread-safe.
class ReputationCache {
public:
    using Clock = std::chrono::system_clock;

    static constexpr std::size_t kMaxCapacity = 10000;

    ReputationCache(std::size_t capacity, std::chrono::seconds timeToLive);

    // The cached report for this provider and hash, unless it is older than the time to live.
    [[nodiscard]] std::optional<ReputationReport>
    find(std::string_view provider, std::string_view sha256, Clock::time_point now);
    void store(const ReputationReport& report);
    void clear() noexcept;

    [[nodiscard]] std::size_t size() const noexcept { return index_.size(); }

private:
    using Entries = std::list<ReputationReport>;

    [[nodiscard]] static std::string keyOf(std::string_view provider, std::string_view sha256);

    std::size_t capacity_;
    std::chrono::seconds timeToLive_;
    // Most recently used first.
    Entries entries_;
    std::unordered_map<std::string, Entries::iterator> index_;
};

} // namespace sectoryn
