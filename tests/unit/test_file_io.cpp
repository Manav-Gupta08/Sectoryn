#include "support/TempDir.hpp"
#include "utilities/FileIo.hpp"

#include <gtest/gtest.h>

#include <string>

namespace sectoryn {
namespace {

TEST(FileIo, WritesNewFile) {
    const test::TempDir dir;
    const auto path = dir.path() / "out.json";
    ASSERT_TRUE(writeFileAtomically(path, "{}\n").hasValue());
    EXPECT_EQ(readSmallFile(path, 16).value(), "{}\n");
}

TEST(FileIo, ReplacesExistingFileAndLeavesNoTemporaries) {
    const test::TempDir dir;
    const auto path = dir.write("out.txt", "old contents that are longer");
    const std::string binary("new\0data", 8);
    ASSERT_TRUE(writeFileAtomically(path, binary).hasValue());
    EXPECT_EQ(readSmallFile(path, 64).value(), binary);

    std::size_t files = 0;
    for ([[maybe_unused]] const auto& entry : std::filesystem::directory_iterator(dir.path())) {
        ++files;
    }
    EXPECT_EQ(files, 1U);
}

TEST(FileIo, WriteFailsForMissingDirectory) {
    const test::TempDir dir;
    const Status status = writeFileAtomically(dir.path() / "missing" / "out.txt", "x");
    ASSERT_FALSE(status.hasValue());
    EXPECT_EQ(status.error().code, ErrorCode::IoFailure);
}

TEST(FileIo, ReadEnforcesTheSizeLimit) {
    const test::TempDir dir;
    const auto path = dir.write("data.txt", "12345");
    EXPECT_EQ(readSmallFile(path, 5).value(), "12345");
    const Result<std::string> tooLarge = readSmallFile(path, 4);
    ASSERT_FALSE(tooLarge.hasValue());
    EXPECT_EQ(tooLarge.error().code, ErrorCode::ResourceLimitExceeded);
}

TEST(FileIo, ReadRefusesDirectoriesAndMissingFiles) {
    const test::TempDir dir;
    EXPECT_FALSE(readSmallFile(dir.path(), 1024).hasValue());
    EXPECT_FALSE(readSmallFile(dir.path() / "missing.txt", 1024).hasValue());
}

} // namespace
} // namespace sectoryn
