#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace sectoryn {

using ByteHistogram = std::array<std::uint64_t, 256>;

inline constexpr double kMaxEntropy = 8.0;

// Shannon entropy in bits per byte: H = -sum(p_i * log2(p_i)) over the byte values present.
// The result lies in [0, 8]; empty input has entropy 0.
[[nodiscard]] double shannonEntropy(const ByteHistogram& histogram, std::uint64_t total) noexcept;
[[nodiscard]] double shannonEntropy(std::span<const std::byte> data) noexcept;

} // namespace sectoryn
