#include "engine/Deduplicator.hpp"

namespace sectoryn {

std::optional<std::uint64_t> Deduplicator::claim(const std::string& sha256, std::uint64_t job) {
    const std::lock_guard lock(mutex_);
    const auto [it, inserted] = owners_.try_emplace(sha256, job);
    if (inserted || it->second == job) {
        return std::nullopt;
    }
    return it->second;
}

void Deduplicator::release(const std::string& sha256, std::uint64_t job) {
    const std::lock_guard lock(mutex_);
    if (const auto it = owners_.find(sha256); it != owners_.end() && it->second == job) {
        owners_.erase(it);
    }
}

void Deduplicator::clear() {
    const std::lock_guard lock(mutex_);
    owners_.clear();
}

std::size_t Deduplicator::size() const {
    const std::lock_guard lock(mutex_);
    return owners_.size();
}

} // namespace sectoryn
