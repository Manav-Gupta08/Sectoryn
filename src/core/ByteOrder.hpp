#pragma once

#include <concepts>
#include <cstddef>
#include <optional>
#include <span>

namespace sectoryn {

// Reads an integer stored at `offset`; nullopt when the data is too short to hold it.
template <std::unsigned_integral T>
[[nodiscard]] constexpr std::optional<T> readLe(std::span<const std::byte> data,
                                                std::size_t offset) noexcept {
    if (offset > data.size() || data.size() - offset < sizeof(T)) {
        return std::nullopt;
    }
    T value = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        value = static_cast<T>(value | (std::to_integer<T>(data[offset + i]) << (8 * i)));
    }
    return value;
}

template <std::unsigned_integral T>
[[nodiscard]] constexpr std::optional<T> readBe(std::span<const std::byte> data,
                                                std::size_t offset) noexcept {
    if (offset > data.size() || data.size() - offset < sizeof(T)) {
        return std::nullopt;
    }
    T value = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        value = static_cast<T>((value << 8) | std::to_integer<T>(data[offset + i]));
    }
    return value;
}

} // namespace sectoryn
