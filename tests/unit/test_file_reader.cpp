#include "support/TempDir.hpp"
#include "utilities/FileReader.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <string>
#include <vector>

namespace sectoryn {
namespace {

std::string asText(std::span<const std::byte> bytes) {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

TEST(FileReader, RejectsMissingFile) {
    const test::TempDir dir;
    const Result<FileReader> reader = FileReader::open(dir.path() / "missing.bin");
    ASSERT_FALSE(reader.hasValue());
    EXPECT_EQ(reader.error().code, ErrorCode::InvalidInput);
}

TEST(FileReader, RejectsDirectory) {
    const test::TempDir dir;
    const Result<FileReader> reader = FileReader::open(dir.path());
    ASSERT_FALSE(reader.hasValue());
    EXPECT_EQ(reader.error().code, ErrorCode::InvalidInput);
}

TEST(FileReader, RejectsEmptyPath) {
    EXPECT_FALSE(FileReader::open({}).hasValue());
}

TEST(FileReader, ReportsSize) {
    const test::TempDir dir;
    Result<FileReader> reader = FileReader::open(dir.write("a.bin", "0123456789"));
    ASSERT_TRUE(reader.hasValue()) << reader.error().describe();
    EXPECT_EQ(reader.value().size(), 10U);
}

TEST(FileReader, OpensEmptyFile) {
    const test::TempDir dir;
    Result<FileReader> reader = FileReader::open(dir.write("empty.bin", ""));
    ASSERT_TRUE(reader.hasValue());
    EXPECT_EQ(reader.value().size(), 0U);

    std::array<std::byte, 1> one{};
    EXPECT_FALSE(reader.value().readExact(0, one).hasValue());
    EXPECT_TRUE(reader.value().readExact(0, {}).hasValue());
}

TEST(FileReader, ReadExactWithinBounds) {
    const test::TempDir dir;
    Result<FileReader> reader = FileReader::open(dir.write("a.bin", "0123456789"));
    ASSERT_TRUE(reader.hasValue());

    std::array<std::byte, 4> buffer{};
    ASSERT_TRUE(reader.value().readExact(3, buffer).hasValue());
    EXPECT_EQ(asText(buffer), "3456");

    ASSERT_TRUE(reader.value().readExact(6, buffer).hasValue());
    EXPECT_EQ(asText(buffer), "6789");
}

TEST(FileReader, ReadExactRejectsOutOfBounds) {
    const test::TempDir dir;
    Result<FileReader> reader = FileReader::open(dir.write("a.bin", "0123456789"));
    ASSERT_TRUE(reader.hasValue());

    std::array<std::byte, 4> buffer{};
    const Status pastEnd = reader.value().readExact(7, buffer);
    ASSERT_FALSE(pastEnd.hasValue());
    EXPECT_EQ(pastEnd.error().code, ErrorCode::MalformedData);

    EXPECT_FALSE(reader.value().readExact(0xFFFFFFFFFFFFFFFFULL, buffer).hasValue());

    // A failed read must not leave the stream unusable.
    ASSERT_TRUE(reader.value().readExact(0, buffer).hasValue());
    EXPECT_EQ(asText(buffer), "0123");
}

TEST(FileReader, StreamsChunks) {
    const test::TempDir dir;
    Result<FileReader> reader = FileReader::open(dir.write("a.bin", "abcdefghij"));
    ASSERT_TRUE(reader.hasValue());

    std::vector<std::string> chunks;
    const Status status = reader.value().forEachChunk(
        {1, 8}, 3, {}, [&chunks](std::span<const std::byte> chunk) {
            chunks.push_back(asText(chunk));
            return Status{};
        });
    ASSERT_TRUE(status.hasValue()) << status.error().describe();
    EXPECT_EQ(chunks, (std::vector<std::string>{"bcd", "efg", "hi"}));
}

TEST(FileReader, StreamRejectsBadArguments) {
    const test::TempDir dir;
    Result<FileReader> reader = FileReader::open(dir.write("a.bin", "abcdefghij"));
    ASSERT_TRUE(reader.hasValue());

    const auto ignore = [](std::span<const std::byte>) { return Status{}; };
    EXPECT_FALSE(reader.value().forEachChunk({0, 10}, 0, {}, ignore).hasValue());
    EXPECT_FALSE(reader.value().forEachChunk({5, 6}, 4, {}, ignore).hasValue());
}

TEST(FileReader, StreamStopsOnHandlerError) {
    const test::TempDir dir;
    Result<FileReader> reader = FileReader::open(dir.write("a.bin", "abcdefghij"));
    ASSERT_TRUE(reader.hasValue());

    int calls = 0;
    const Status status = reader.value().forEachChunk(
        {0, 10}, 2, {}, [&calls](std::span<const std::byte>) -> Status {
            ++calls;
            return Error{ErrorCode::MalformedData, "stop"};
        });
    ASSERT_FALSE(status.hasValue());
    EXPECT_EQ(status.error().code, ErrorCode::MalformedData);
    EXPECT_EQ(calls, 1);
}

TEST(FileReader, StreamHonorsCancellation) {
    const test::TempDir dir;
    Result<FileReader> reader = FileReader::open(dir.write("a.bin", "abcdefghij"));
    ASSERT_TRUE(reader.hasValue());

    CancellationSource source;
    int calls = 0;
    const Status status = reader.value().forEachChunk(
        {0, 10}, 2, source.get_token(), [&](std::span<const std::byte>) {
            if (++calls == 2) {
                source.request_stop();
            }
            return Status{};
        });
    ASSERT_FALSE(status.hasValue());
    EXPECT_EQ(status.error().code, ErrorCode::Cancelled);
    EXPECT_EQ(calls, 2);
}

} // namespace
} // namespace sectoryn
