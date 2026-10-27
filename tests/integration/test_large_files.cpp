#include "engine/AnalysisEngine.hpp"
#include "support/PeBuilder.hpp"
#include "support/TempDir.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

namespace sectoryn {
namespace {

using test::bytesOf;
using test::PeBuilder;

AnalysisEngine engineWith(const AnalysisLimits& limits) {
    Result<AnalysisEngine> engine = AnalysisEngine::createDefault({limits, {}});
    EXPECT_TRUE(engine.hasValue()) << engine.error().describe();
    return std::move(engine).value();
}

// A valid PE padded with an overlay so the whole file is exactly `size` bytes.
std::vector<std::byte> peOfSize(std::size_t size, std::byte fill) {
    std::vector<std::byte> file =
        PeBuilder().addSection(".text", PeBuilder::kCode, bytesOf(std::string(0x200, '\xC3'))).build();
    if (file.size() < size) {
        file.resize(size, fill);
    }
    return file;
}

bool hasGap(const AnalysisResult& result, std::string_view text) {
    return std::ranges::any_of(result.risk.coverageGaps, [text](const std::string& gap) {
        return gap.find(text) != std::string::npos;
    });
}

TEST(LargeFiles, FileAtTheSizeLimitIsAnalyzed) {
    AnalysisLimits limits;
    limits.maxFileBytes = 2 * kMiB;
    const test::TempDir dir;
    const Result<AnalysisResult> result = engineWith(limits).analyze(
        dir.write("limit.exe", peOfSize(static_cast<std::size_t>(limits.maxFileBytes),
                                        std::byte{0})));
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
    EXPECT_EQ(result.value().file.sizeBytes, limits.maxFileBytes);
    ASSERT_TRUE(result.value().pe.has_value());
}

TEST(LargeFiles, FileOneByteOverTheLimitIsRejected) {
    AnalysisLimits limits;
    limits.maxFileBytes = 2 * kMiB;
    const test::TempDir dir;
    const Result<AnalysisResult> result = engineWith(limits).analyze(
        dir.write("over.exe", peOfSize(static_cast<std::size_t>(limits.maxFileBytes) + 1,
                                       std::byte{0})));
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error().code, ErrorCode::ResourceLimitExceeded);
}

TEST(LargeFiles, StringLimitIsEnforcedAndReported) {
    AnalysisLimits limits;
    limits.maxStrings = 1000;
    // "abcdefgh\0" repeated: about 900,000 candidate strings in 8 MiB.
    std::vector<std::byte> file = peOfSize(0, std::byte{0});
    const std::vector<std::byte> unit = bytesOf(std::string("abcdefgh\0", 9));
    while (file.size() < 8 * kMiB) {
        file.insert(file.end(), unit.begin(), unit.end());
    }
    const test::TempDir dir;
    const Result<AnalysisResult> result = engineWith(limits).analyze(dir.write("strings.exe", file));
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
    ASSERT_TRUE(result.value().strings.has_value());
    EXPECT_LE(result.value().strings->strings.size(), limits.maxStrings);
    EXPECT_TRUE(result.value().strings->limitReached);
    EXPECT_TRUE(hasGap(result.value(), "strings"));
    EXPECT_NE(result.value().risk.outcome, TriageOutcome::NoSignificantIndicators);
}

TEST(LargeFiles, LargeOverlayIsHashedAndMeasuredInChunks) {
    AnalysisLimits limits;
    limits.readChunkBytes = 4096;
    const test::TempDir dir;
    const Result<AnalysisResult> result =
        engineWith(limits).analyze(dir.write("big.exe", peOfSize(24 * kMiB, std::byte{0x41})));
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
    ASSERT_TRUE(result.value().pe.has_value());
    EXPECT_EQ(result.value().pe->overlay.status.state, FieldState::Present);
    EXPECT_EQ(result.value().sha256.size(), 64U);
    ASSERT_TRUE(result.value().entropy.has_value());
    ASSERT_TRUE(result.value().entropy->overlay.entropy.has_value());
    EXPECT_LT(*result.value().entropy->overlay.entropy, 0.01);
}

TEST(LargeFiles, CancellationStopsALargeAnalysis) {
    CancellationSource source;
    source.request_stop();
    const test::TempDir dir;
    const Result<AnalysisResult> result =
        engineWith({}).analyze(dir.write("cancel.exe", peOfSize(16 * kMiB, std::byte{0x41})),
                               source.get_token());
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error().code, ErrorCode::Cancelled);
}

} // namespace
} // namespace sectoryn
