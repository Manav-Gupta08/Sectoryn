#include "analysis/FileIntake.hpp"
#include "support/TempDir.hpp"

#include <gtest/gtest.h>

#include <string>

namespace sectoryn {
namespace {

TEST(FileIntake, OpensRegularFile) {
    const test::TempDir dir;
    const auto path = dir.write("sample.exe", "MZ data");
    Result<OpenedFile> file = openForAnalysis(path, AnalysisLimits{});
    ASSERT_TRUE(file.hasValue()) << file.error().describe();
    EXPECT_EQ(file.value().metadata.path, path);
    EXPECT_EQ(file.value().metadata.sizeBytes, 7U);
    EXPECT_EQ(file.value().reader.size(), 7U);
    EXPECT_TRUE(file.value().metadata.lastWriteTime.has_value());
}

TEST(FileIntake, RejectsEmptyFile) {
    const test::TempDir dir;
    const Result<OpenedFile> file = openForAnalysis(dir.write("empty.exe", ""), AnalysisLimits{});
    ASSERT_FALSE(file.hasValue());
    EXPECT_EQ(file.error().code, ErrorCode::InvalidInput);
}

TEST(FileIntake, EnforcesSizeLimit) {
    const test::TempDir dir;
    AnalysisLimits limits;
    limits.maxFileBytes = 16;

    EXPECT_TRUE(openForAnalysis(dir.write("fits.bin", std::string(16, 'a')), limits).hasValue());

    const Result<OpenedFile> tooBig =
        openForAnalysis(dir.write("big.bin", std::string(17, 'a')), limits);
    ASSERT_FALSE(tooBig.hasValue());
    EXPECT_EQ(tooBig.error().code, ErrorCode::ResourceLimitExceeded);
}

TEST(FileIntake, RejectsDirectoryAndMissingFile) {
    const test::TempDir dir;
    EXPECT_FALSE(openForAnalysis(dir.path(), AnalysisLimits{}).hasValue());
    EXPECT_FALSE(openForAnalysis(dir.path() / "nope.exe", AnalysisLimits{}).hasValue());
}

} // namespace
} // namespace sectoryn
