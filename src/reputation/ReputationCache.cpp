#include "reputation/ReputationCache.hpp"

#include <algorithm>
#include <cctype>

namespace sectoryn {

ReputationCache::ReputationCache(std::size_t capacity, std::chrono::seconds timeToLive)
    : capacity_(std::clamp<std::size_t>(capacity, 1, kMaxCapacity))
    , timeToLive_(std::max(timeToLive, std::chrono::seconds{0})) {}

std::string ReputationCache::keyOf(std::string_view provider, std::string_view sha256) {
    std::string key(provider);
    key += ':';
    for (const char c : sha256) {
        key += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return key;
}

std::optional<ReputationReport>
ReputationCache::find(std::string_view provider, std::string_view sha256, Clock::time_point now) {
    const auto it = index_.find(keyOf(provider, sha256));
    if (it == index_.end()) {
        return std::nullopt;
    }
    const Entries::iterator entry = it->second;
    // Reports from the future (a clock change) are treated as expired too.
    if (entry->retrievedAt > now || now - entry->retrievedAt > timeToLive_) {
        entries_.erase(entry);
        index_.erase(it);
        return std::nullopt;
    }
    entries_.splice(entries_.begin(), entries_, entry);
    return *entry;
}

void ReputationCache::store(const ReputationReport& report) {
    const std::string key = keyOf(report.provider, report.sha256);
    if (const auto it = index_.find(key); it != index_.end()) {
        entries_.erase(it->second);
        index_.erase(it);
    }
    entries_.push_front(report);
    index_.emplace(key, entries_.begin());
    while (index_.size() > capacity_) {
        index_.erase(keyOf(entries_.back().provider, entries_.back().sha256));
        entries_.pop_back();
    }
}

void ReputationCache::clear() noexcept {
    index_.clear();
    entries_.clear();
}

} // namespace sectoryn
