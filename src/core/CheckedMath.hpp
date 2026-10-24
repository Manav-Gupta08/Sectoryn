#pragma once

#include <concepts>
#include <cstdint>
#include <limits>
#include <optional>
#include <utility>

// Arithmetic on values read from untrusted files. Every helper reports overflow instead of
// wrapping, so a crafted header cannot turn an out-of-range offset into a small valid one.

namespace sectoryn {

template <std::unsigned_integral T>
[[nodiscard]] constexpr std::optional<T> checkedAdd(T a, T b) noexcept {
    if (b > std::numeric_limits<T>::max() - a) {
        return std::nullopt;
    }
    return static_cast<T>(a + b);
}

template <std::unsigned_integral T>
[[nodiscard]] constexpr std::optional<T> checkedSub(T a, T b) noexcept {
    if (b > a) {
        return std::nullopt;
    }
    return static_cast<T>(a - b);
}

template <std::unsigned_integral T>
[[nodiscard]] constexpr std::optional<T> checkedMul(T a, T b) noexcept {
    if (a != 0 && b > std::numeric_limits<T>::max() / a) {
        return std::nullopt;
    }
    return static_cast<T>(a * b);
}

template <std::integral To, std::integral From>
[[nodiscard]] constexpr std::optional<To> checkedCast(From value) noexcept {
    if (!std::in_range<To>(value)) {
        return std::nullopt;
    }
    return static_cast<To>(value);
}

// Rounds up to a multiple of alignment. PE alignments are normally powers of two, but
// malformed headers may contain anything, so no such assumption is made here.
template <std::unsigned_integral T>
[[nodiscard]] constexpr std::optional<T> alignUp(T value, T alignment) noexcept {
    if (alignment == 0) {
        return value;
    }
    const T remainder = value % alignment;
    if (remainder == 0) {
        return value;
    }
    return checkedAdd<T>(value, static_cast<T>(alignment - remainder));
}

// True when [offset, offset + size) lies entirely within [0, limit).
[[nodiscard]] constexpr bool rangeFits(std::uint64_t offset, std::uint64_t size,
                                       std::uint64_t limit) noexcept {
    return offset <= limit && size <= limit - offset;
}

// Half-open byte range [offset, offset + size).
struct ByteRange {
    std::uint64_t offset = 0;
    std::uint64_t size = 0;

    [[nodiscard]] constexpr std::optional<std::uint64_t> end() const noexcept {
        return checkedAdd(offset, size);
    }

    [[nodiscard]] constexpr bool empty() const noexcept { return size == 0; }

    [[nodiscard]] constexpr bool contains(std::uint64_t position) const noexcept {
        return position >= offset && position - offset < size;
    }

    [[nodiscard]] constexpr bool fitsWithin(std::uint64_t limit) const noexcept {
        return rangeFits(offset, size, limit);
    }

    // Empty ranges never overlap anything. Written without computing end() so that ranges
    // whose end would overflow are still compared correctly.
    [[nodiscard]] constexpr bool overlaps(const ByteRange& other) const noexcept {
        if (empty() || other.empty()) {
            return false;
        }
        return offset <= other.offset ? other.offset - offset < size
                                      : offset - other.offset < other.size;
    }

    friend constexpr bool operator==(const ByteRange&, const ByteRange&) = default;
};

} // namespace sectoryn
