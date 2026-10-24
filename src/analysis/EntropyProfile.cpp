#include "analysis/EntropyProfile.hpp"

#include <algorithm>
#include <utility>

namespace sectoryn {

EntropyProfile::EntropyProfile(std::uint64_t totalBytes, std::uint64_t startOffset)
    : blockSize_(std::max(kMinBlockBytes, (totalBytes + kMaxPoints - 1) / kMaxPoints))
    , blockStart_(startOffset) {
    points_.reserve(static_cast<std::size_t>(
        std::min<std::uint64_t>(kMaxPoints, (totalBytes + blockSize_ - 1) / blockSize_)));
}

void EntropyProfile::add(std::span<const std::byte> data) {
    while (!data.empty()) {
        const std::uint64_t room = blockSize_ - block_.total();
        const auto take = static_cast<std::size_t>(std::min<std::uint64_t>(room, data.size()));
        block_.add(data.first(take));
        data = data.subspan(take);
        if (block_.total() == blockSize_) {
            closeBlock();
        }
    }
}

std::vector<EntropyPoint> EntropyProfile::finish() {
    if (block_.total() != 0) {
        closeBlock();
    }
    return std::exchange(points_, {});
}

void EntropyProfile::closeBlock() {
    points_.push_back({blockStart_, block_.total(), block_.entropy()});
    blockStart_ += block_.total();
    block_ = {};
}

} // namespace sectoryn
