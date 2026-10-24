#include "analysis/ByteStatistics.hpp"
#include "analysis/EntropyAnalyzer.hpp"
#include "analysis/EntropyProfile.hpp"
#include "support/TempDir.hpp"
#include "utilities/FileReader.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace sectoryn {
namespace {

constexpr double kTolerance = 1e-9;

std::string uniformBytes(std::size_t rounds) {
    std::string data;
    for (std::size_t r = 0; r < rounds; ++r) {
        for (int value = 0; value < 256; ++value) {
            data.push_back(static_cast<char>(value));
        }
    }
    return data;
}

// Layout: 1 KiB zeros, 1 KiB of every byte value, 1 KiB of "ab", 1 KiB of every byte value.
std::string sampleFile() {
    std::string data(0x400, '\0');
    data += uniformBytes(4);
    for (int i = 0; i < 0x200; ++i) {
        data += "ab";
    }
    data += uniformBytes(4);
    return data;
}

SectionAssessment readable(std::uint64_t offset, std::uint64_t size) {
    SectionAssessment assessment;
    assessment.readableRange = {offset, size};
    return assessment;
}

TEST(ByteStatistics, AccumulatesAcrossCalls) {
    ByteStatistics stats;
    const std::string_view first = "aab";
    const std::string_view second = "bcc";
    stats.add(std::as_bytes(std::span(first)));
    stats.add(std::as_bytes(std::span(second)));
    EXPECT_EQ(stats.total(), 6U);
    EXPECT_EQ(stats.distinctValues(), 3U);
    EXPECT_NEAR(stats.fraction('a'), 2.0 / 6.0, kTolerance);
    EXPECT_NEAR(stats.entropy(), std::log2(3.0), kTolerance);
    EXPECT_EQ(ByteStatistics{}.fraction(0), 0.0);
}

TEST(EntropyProfile, ChoosesBlockSize) {
    EXPECT_EQ(EntropyProfile(100).blockSize(), EntropyProfile::kMinBlockBytes);
    EXPECT_EQ(EntropyProfile(10'000'000).blockSize(), 9766U);
}

TEST(EntropyProfile, ProducesBoundedPoints) {
    const std::string data(300'000, 'x');
    EntropyProfile profile(data.size());
    profile.add(std::as_bytes(std::span(data)));
    const std::vector<EntropyPoint> points = profile.finish();
    EXPECT_LE(points.size(), EntropyProfile::kMaxPoints);
    std::uint64_t covered = 0;
    for (const EntropyPoint& point : points) {
        EXPECT_EQ(point.offset, covered);
        covered += point.size;
    }
    EXPECT_EQ(covered, data.size());
}

TEST(EntropyProfile, ChunkingDoesNotChangeResult) {
    const std::string data = sampleFile();
    EntropyProfile whole(data.size());
    whole.add(std::as_bytes(std::span(data)));
    const std::vector<EntropyPoint> expected = whole.finish();

    EntropyProfile pieces(data.size());
    constexpr std::size_t kPiece = 77;
    for (std::size_t pos = 0; pos < data.size(); pos += kPiece) {
        const std::size_t length = std::min(kPiece, data.size() - pos);
        pieces.add(std::as_bytes(std::span(data).subspan(pos, length)));
    }
    const std::vector<EntropyPoint> actual = pieces.finish();
    ASSERT_EQ(actual.size(), expected.size());
    for (std::size_t i = 0; i < actual.size(); ++i) {
        EXPECT_EQ(actual[i].offset, expected[i].offset);
        EXPECT_DOUBLE_EQ(actual[i].entropy, expected[i].entropy);
    }
}

class EntropyAnalyzerTest : public ::testing::Test {
protected:
    void SetUp() override {
        data_ = sampleFile();
        Result<FileReader> opened = FileReader::open(dir_.write("sample.bin", data_));
        ASSERT_TRUE(opened.hasValue());
        reader_.emplace(std::move(opened).value());
        limits_.readChunkBytes = 4096;
    }

    test::TempDir dir_;
    std::string data_;
    std::optional<FileReader> reader_;
    AnalysisLimits limits_;
};

TEST_F(EntropyAnalyzerTest, MeasuresFileSectionsAndOverlay) {
    SectionAnalysis sections;
    sections.sections = {readable(0x400, 0x400), readable(0x800, 0x400), readable(0, 0)};
    Overlay overlay;
    overlay.status = FieldStatus::present();
    overlay.fileOffset = 0xC00;
    overlay.size = 0x400;

    const Result<EntropyReport> result = analyzeEntropy(*reader_, sections, overlay, limits_, {});
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
    const EntropyReport& report = result.value();

    EXPECT_EQ(report.file.total(), data_.size());
    EXPECT_NEAR(report.file.entropy(), shannonEntropy(std::as_bytes(std::span(data_))), kTolerance);

    ASSERT_EQ(report.sections.size(), 3U);
    EXPECT_NEAR(report.sections[0].entropy.value_or(-1), 8.0, kTolerance);
    EXPECT_EQ(report.sections[0].bytes, 0x400U);
    EXPECT_NEAR(report.sections[1].entropy.value_or(-1), 1.0, kTolerance);
    EXPECT_FALSE(report.sections[2].entropy.has_value());
    EXPECT_NEAR(report.overlay.entropy.value_or(-1), 8.0, kTolerance);
    EXPECT_FALSE(report.sectionBudgetExhausted);

    EXPECT_EQ(report.profileBlockSize, EntropyProfile::kMinBlockBytes);
    ASSERT_EQ(report.profile.size(), 16U);
    EXPECT_NEAR(report.profile[0].entropy, 0.0, kTolerance);
    EXPECT_NEAR(report.profile[4].entropy, 8.0, kTolerance);
    EXPECT_NEAR(report.profile[8].entropy, 1.0, kTolerance);
}

TEST_F(EntropyAnalyzerTest, OverlayNotMeasuredWhenAbsent) {
    const Result<EntropyReport> result = analyzeEntropy(*reader_, {}, Overlay{}, limits_, {});
    ASSERT_TRUE(result.hasValue());
    EXPECT_FALSE(result.value().overlay.entropy.has_value());
}

TEST_F(EntropyAnalyzerTest, OverlappingSectionsAreBudgeted) {
    SectionAnalysis sections;
    for (int i = 0; i < 5; ++i) {
        sections.sections.push_back(readable(0, data_.size()));
    }
    const Result<EntropyReport> result = analyzeEntropy(*reader_, sections, Overlay{}, limits_, {});
    ASSERT_TRUE(result.hasValue());
    const EntropyReport& report = result.value();
    EXPECT_TRUE(report.sectionBudgetExhausted);
    EXPECT_TRUE(report.sections[1].entropy.has_value());
    EXPECT_FALSE(report.sections[2].entropy.has_value());
    EXPECT_EQ(report.sections[2].bytes, data_.size());
}

TEST_F(EntropyAnalyzerTest, IsCancellable) {
    CancellationSource source;
    source.request_stop();
    const Result<EntropyReport> result =
        analyzeEntropy(*reader_, {}, Overlay{}, limits_, source.get_token());
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error().code, ErrorCode::Cancelled);
}

} // namespace
} // namespace sectoryn
