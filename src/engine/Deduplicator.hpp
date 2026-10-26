#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace sectoryn {

// Remembers which file contents a batch has already taken on, so the same file queued twice
// under different names is analyzed once. Safe to use from several threads.
class Deduplicator {
public:
    // Returns the job that first claimed `sha256`, or nothing if `job` is now its owner.
    [[nodiscard]] std::optional<std::uint64_t> claim(const std::string& sha256, std::uint64_t job);

    // Gives up a claim, e.g. because the owning job was cancelled before it produced a result.
    // Claims held by other jobs are left alone.
    void release(const std::string& sha256, std::uint64_t job);

    void clear();
    [[nodiscard]] std::size_t size() const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::uint64_t> owners_;
};

} // namespace sectoryn
