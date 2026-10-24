#include "support/TempDir.hpp"
#include "utilities/FileReader.hpp"
#include "utilities/Sha256.hpp"

#include <gtest/gtest.h>

#include <string>
#include <string_view>

namespace sectoryn {
namespace {

std::span<const std::byte> bytesOf(std::string_view text) {
    return std::as_bytes(std::span(text));
}

std::string hexOf(std::string_view text) {
    const Result<Sha256::Digest> digest = Sha256::hash(bytesOf(text));
    if (!digest) {
        return digest.error().describe();
    }
    return Sha256::toHex(digest.value());
}

// Test vectors from NIST FIPS 180-4 example values.
TEST(Sha256, EmptyInput) {
    EXPECT_EQ(hexOf(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(Sha256, Abc) {
    EXPECT_EQ(hexOf("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Sha256, TwoBlockMessage) {
    EXPECT_EQ(hexOf("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST(Sha256, OneMillionA) {
    const std::string input(1000000, 'a');
    EXPECT_EQ(hexOf(input), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST(Sha256, IncrementalMatchesOneShot) {
    const std::string_view text = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    Result<Sha256> hasher = Sha256::create();
    ASSERT_TRUE(hasher.hasValue());
    for (std::size_t i = 0; i < text.size(); i += 7) {
        ASSERT_TRUE(hasher.value().update(bytesOf(text.substr(i, 7))).hasValue());
    }
    const Result<Sha256::Digest> digest = hasher.value().finish();
    ASSERT_TRUE(digest.hasValue());
    EXPECT_EQ(Sha256::toHex(digest.value()), hexOf(text));
}

TEST(Sha256, CannotBeReusedAfterFinish) {
    Result<Sha256> hasher = Sha256::create();
    ASSERT_TRUE(hasher.hasValue());
    ASSERT_TRUE(hasher.value().finish().hasValue());
    EXPECT_FALSE(hasher.value().update(bytesOf("x")).hasValue());
    EXPECT_FALSE(hasher.value().finish().hasValue());
}

TEST(Sha256, HashesFileInChunks) {
    const test::TempDir dir;
    const std::string contents(100003, 'a');
    Result<FileReader> reader = FileReader::open(dir.write("data.bin", contents));
    ASSERT_TRUE(reader.hasValue());

    const Result<Sha256::Digest> digest = sha256File(reader.value(), 4096, {});
    ASSERT_TRUE(digest.hasValue()) << digest.error().describe();
    EXPECT_EQ(Sha256::toHex(digest.value()), hexOf(contents));
}

TEST(Sha256, HashesEmptyFile) {
    const test::TempDir dir;
    Result<FileReader> reader = FileReader::open(dir.write("empty.bin", ""));
    ASSERT_TRUE(reader.hasValue());

    const Result<Sha256::Digest> digest = sha256File(reader.value(), 4096, {});
    ASSERT_TRUE(digest.hasValue());
    EXPECT_EQ(Sha256::toHex(digest.value()), hexOf(""));
}

TEST(Sha256, FileHashingIsCancellable) {
    const test::TempDir dir;
    Result<FileReader> reader = FileReader::open(dir.write("data.bin", std::string(8192, 'z')));
    ASSERT_TRUE(reader.hasValue());

    CancellationSource source;
    source.request_stop();
    const Result<Sha256::Digest> digest = sha256File(reader.value(), 4096, source.get_token());
    ASSERT_FALSE(digest.hasValue());
    EXPECT_EQ(digest.error().code, ErrorCode::Cancelled);
}

} // namespace
} // namespace sectoryn
