#pragma once

#include "analysis/ByteStatistics.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace sectoryn {

struct EntropyPoint {
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    double entropy = 0.0;
};

// Entropy of consecutive fixed-size blocks across a byte range, for plotting how entropy
// changes through a file. The block size is chosen so that at most kMaxPoints are produced.
class EntropyProfile {
public:
    static constexpr std::size_t kMaxPoints = 1024;
    // Below this, a block holds too few bytes for its entropy to say much.
    static constexpr std::uint64_t kMinBlockBytes = 256;

    // `totalBytes` is the length of the range that will be fed, starting at `startOffset`.
    explicit EntropyProfile(std::uint64_t totalBytes, std::uint64_t startOffset = 0);

    void add(std::span<const std::byte> data);
    [[nodiscard]] std::vector<EntropyPoint> finish();

    [[nodiscard]] std::uint64_t blockSize() const noexcept { return blockSize_; }

private:
    void closeBlock();

    std::uint64_t blockSize_;
    std::uint64_t blockStart_;
    ByteStatistics block_;
    std::vector<EntropyPoint> points_;
};

} // namespace sectoryn
