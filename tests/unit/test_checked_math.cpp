#include "core/CheckedMath.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <limits>

namespace sectoryn {
namespace {

constexpr auto kMax64 = std::numeric_limits<std::uint64_t>::max();
constexpr auto kMax32 = std::numeric_limits<std::uint32_t>::max();

TEST(CheckedMath, AddDetectsOverflow) {
    EXPECT_EQ(checkedAdd<std::uint32_t>(1, 2), 3U);
    EXPECT_EQ(checkedAdd<std::uint32_t>(kMax32 - 1, 1), kMax32);
    EXPECT_FALSE(checkedAdd<std::uint32_t>(kMax32, 1).has_value());
    EXPECT_FALSE(checkedAdd<std::uint64_t>(kMax64, kMax64).has_value());
}

TEST(CheckedMath, SubDetectsUnderflow) {
    EXPECT_EQ(checkedSub<std::uint32_t>(5, 5), 0U);
    EXPECT_FALSE(checkedSub<std::uint32_t>(4, 5).has_value());
}

TEST(CheckedMath, MulDetectsOverflow) {
    EXPECT_EQ(checkedMul<std::uint64_t>(0, kMax64), 0U);
    EXPECT_EQ(checkedMul<std::uint64_t>(kMax64, 1), kMax64);
    EXPECT_EQ(checkedMul<std::uint32_t>(0x10000, 0xFFFF), 0xFFFF0000U);
    EXPECT_FALSE(checkedMul<std::uint32_t>(0x10000, 0x10000).has_value());
}

TEST(CheckedMath, CastRejectsValuesOutOfRange) {
    EXPECT_EQ(checkedCast<std::uint16_t>(65535), 65535);
    EXPECT_FALSE(checkedCast<std::uint16_t>(65536).has_value());
    EXPECT_FALSE(checkedCast<std::uint32_t>(-1).has_value());
    EXPECT_FALSE(checkedCast<std::int64_t>(kMax64).has_value());
    EXPECT_EQ(checkedCast<std::int32_t>(std::uint8_t{200}), 200);
}

TEST(CheckedMath, AlignUp) {
    EXPECT_EQ(alignUp<std::uint32_t>(0, 0x200), 0U);
    EXPECT_EQ(alignUp<std::uint32_t>(1, 0x200), 0x200U);
    EXPECT_EQ(alignUp<std::uint32_t>(0x200, 0x200), 0x200U);
    EXPECT_EQ(alignUp<std::uint32_t>(0x201, 0x200), 0x400U);
    EXPECT_EQ(alignUp<std::uint32_t>(7, 3), 9U);
    EXPECT_EQ(alignUp<std::uint32_t>(123, 0), 123U);
    EXPECT_FALSE(alignUp<std::uint32_t>(kMax32, 0x1000).has_value());
}

TEST(CheckedMath, RangeFits) {
    EXPECT_TRUE(rangeFits(0, 0, 0));
    EXPECT_TRUE(rangeFits(0, 100, 100));
    EXPECT_TRUE(rangeFits(100, 0, 100));
    EXPECT_FALSE(rangeFits(101, 0, 100));
    EXPECT_FALSE(rangeFits(50, 51, 100));
    EXPECT_FALSE(rangeFits(1, kMax64, kMax64));
    EXPECT_FALSE(rangeFits(kMax64, 2, 100));
}

TEST(ByteRange, EndReportsOverflow) {
    EXPECT_EQ((ByteRange{10, 20}.end()), 30U);
    EXPECT_FALSE((ByteRange{kMax64, 1}.end()).has_value());
}

TEST(ByteRange, Contains) {
    const ByteRange range{0x400, 0x200};
    EXPECT_FALSE(range.contains(0x3FF));
    EXPECT_TRUE(range.contains(0x400));
    EXPECT_TRUE(range.contains(0x5FF));
    EXPECT_FALSE(range.contains(0x600));
    EXPECT_FALSE((ByteRange{5, 0}.contains(5)));
}

TEST(ByteRange, Overlaps) {
    const ByteRange a{0x400, 0x200};
    EXPECT_TRUE(a.overlaps({0x500, 0x10}));
    EXPECT_TRUE(a.overlaps({0x300, 0x101}));
    EXPECT_FALSE(a.overlaps({0x300, 0x100}));
    EXPECT_FALSE(a.overlaps({0x600, 0x100}));
    EXPECT_FALSE(a.overlaps({0x500, 0}));
    EXPECT_TRUE(a.overlaps(a));
}

TEST(ByteRange, OverlapsHandlesRangesThatWouldOverflow) {
    const ByteRange huge{kMax64 - 10, kMax64};
    EXPECT_TRUE(huge.overlaps({kMax64 - 1, 1}));
    EXPECT_FALSE(huge.overlaps({0, kMax64 - 10}));
    EXPECT_TRUE((ByteRange{0, kMax64}.overlaps(huge)));
}

TEST(ByteRange, FitsWithin) {
    EXPECT_TRUE((ByteRange{0x400, 0x200}.fitsWithin(0x600)));
    EXPECT_FALSE((ByteRange{0x400, 0x201}.fitsWithin(0x600)));
}

} // namespace
} // namespace sectoryn
