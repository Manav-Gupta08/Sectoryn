#pragma once

#include "analysis/Entropy.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace sectoryn {

// Byte-value histogram built incrementally, so statistics for large ranges never need the
// whole range in memory.
class ByteStatistics {
public:
    void add(std::span<const std::byte> data) noexcept;

    [[nodiscard]] std::uint64_t total() const noexcept { return total_; }
    [[nodiscard]] const ByteHistogram& histogram() const noexcept { return histogram_; }
    [[nodiscard]] double entropy() const noexcept { return shannonEntropy(histogram_, total_); }
    [[nodiscard]] std::size_t distinctValues() const noexcept;
    // Fraction of bytes equal to `value`; 0 for empty input.
    [[nodiscard]] double fraction(std::uint8_t value) const noexcept;

private:
    ByteHistogram histogram_{};
    std::uint64_t total_ = 0;
};

} // namespace sectoryn
