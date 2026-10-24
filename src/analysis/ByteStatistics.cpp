#include "analysis/ByteStatistics.hpp"

#include <algorithm>

namespace sectoryn {

void ByteStatistics::add(std::span<const std::byte> data) noexcept {
    for (const std::byte b : data) {
        ++histogram_[std::to_integer<std::size_t>(b)];
    }
    total_ += data.size();
}

std::size_t ByteStatistics::distinctValues() const noexcept {
    return static_cast<std::size_t>(
        std::ranges::count_if(histogram_, [](std::uint64_t count) { return count != 0; }));
}

double ByteStatistics::fraction(std::uint8_t value) const noexcept {
    if (total_ == 0) {
        return 0.0;
    }
    return static_cast<double>(histogram_[value]) / static_cast<double>(total_);
}

} // namespace sectoryn
