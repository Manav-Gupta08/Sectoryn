#include "analysis/Entropy.hpp"

#include <algorithm>
#include <cmath>

namespace sectoryn {

double shannonEntropy(const ByteHistogram& histogram, std::uint64_t total) noexcept {
    if (total == 0) {
        return 0.0;
    }
    const auto n = static_cast<double>(total);
    double entropy = 0.0;
    for (const std::uint64_t count : histogram) {
        if (count != 0) {
            const double p = static_cast<double>(count) / n;
            entropy -= p * std::log2(p);
        }
    }
    // Rounding can leave tiny excursions outside the mathematical range.
    return std::clamp(entropy, 0.0, kMaxEntropy);
}

double shannonEntropy(std::span<const std::byte> data) noexcept {
    ByteHistogram histogram{};
    for (const std::byte b : data) {
        ++histogram[std::to_integer<std::size_t>(b)];
    }
    return shannonEntropy(histogram, data.size());
}

} // namespace sectoryn
