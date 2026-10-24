#include "analysis/Entropy.hpp"

#include <gtest/gtest.h>

#include <string_view>
#include <vector>

namespace sectoryn {
namespace {

constexpr double kTolerance = 1e-9;

double entropyOf(std::string_view text) {
    return shannonEntropy(std::as_bytes(std::span(text)));
}

TEST(Entropy, EmptyInputIsZero) {
    EXPECT_EQ(shannonEntropy(std::span<const std::byte>{}), 0.0);
    EXPECT_EQ(shannonEntropy(ByteHistogram{}, 0), 0.0);
}

TEST(Entropy, SingleValueIsZero) {
    EXPECT_NEAR(entropyOf("aaaaaaaaaaaaaaaa"), 0.0, kTolerance);
}

TEST(Entropy, TwoEquallyLikelyValuesIsOneBit) {
    EXPECT_NEAR(entropyOf("abababab"), 1.0, kTolerance);
}

TEST(Entropy, FourEquallyLikelyValuesIsTwoBits) {
    EXPECT_NEAR(entropyOf("abcdabcdabcd"), 2.0, kTolerance);
}

TEST(Entropy, UnevenDistribution) {
    // p = 2/3 and 1/3: -(2/3)log2(2/3) - (1/3)log2(1/3) = 0.918295834...
    EXPECT_NEAR(entropyOf("aab"), 0.9182958340544896, kTolerance);
}

TEST(Entropy, UniformBytesReachMaximum) {
    std::vector<std::byte> data;
    for (int round = 0; round < 4; ++round) {
        for (int value = 0; value < 256; ++value) {
            data.push_back(static_cast<std::byte>(value));
        }
    }
    EXPECT_NEAR(shannonEntropy(data), kMaxEntropy, kTolerance);
}

TEST(Entropy, HistogramAndSpanAgree) {
    const std::string_view text = "The quick brown fox jumps over the lazy dog";
    ByteHistogram histogram{};
    for (const char c : text) {
        ++histogram[static_cast<unsigned char>(c)];
    }
    EXPECT_DOUBLE_EQ(shannonEntropy(histogram, text.size()), entropyOf(text));
}

} // namespace
} // namespace sectoryn
