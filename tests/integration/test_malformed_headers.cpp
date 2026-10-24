#include "parsers/LiefPeParser.hpp"
#include "parsers/PeConstants.hpp"
#include "support/PeBuilder.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <random>
#include <string>
#include <vector>

namespace sectoryn {
namespace {

using test::bytesOf;
using test::PeBuilder;
using test::writeLe16;
using test::writeLe32;

// Offsets inside the PE32 optional header.
constexpr std::size_t kEntryPointField = PeBuilder::kOptionalHeaderOffset + 16;
constexpr std::size_t kFileAlignmentField = PeBuilder::kOptionalHeaderOffset + 36;
constexpr std::size_t kSizeOfHeadersField = PeBuilder::kOptionalHeaderOffset + 60;
constexpr std::size_t kNumberOfRvaAndSizesField = PeBuilder::kOptionalHeaderOffset + 92;
constexpr std::size_t kNumberOfSectionsField = PeBuilder::kCoffHeaderOffset + 2;
constexpr std::size_t kCharacteristicsField = PeBuilder::kCoffHeaderOffset + 18;

Result<PeImage> parsePe(const std::vector<std::byte>& file) {
    return LiefPeParser{}.parse(file, AnalysisLimits{}, {});
}

PeBuilder sampleBuilder() {
    PeBuilder builder;
    builder.addSection(".text", PeBuilder::kCode, bytesOf(std::string(0x100, '\x90')))
        .addSection(".data", PeBuilder::kReadWrite, bytesOf("data"))
        .addImport("KERNEL32.dll", {"ExitProcess"});
    return builder;
}

bool hasIssue(const PeImage& image, std::string_view code) {
    return std::ranges::any_of(image.issues,
                               [code](const StructuralIssue& issue) { return issue.code == code; });
}

TEST(MalformedHeaders, FileEndsInsideDosHeader) {
    std::vector<std::byte> file = sampleBuilder().build();
    file.resize(0x30);
    const Result<PeImage> result = parsePe(file);
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error().code, ErrorCode::MalformedData);
}

TEST(MalformedHeaders, FileEndsInsideCoffHeader) {
    std::vector<std::byte> file = sampleBuilder().build();
    file.resize(PeBuilder::kCoffHeaderOffset + 10);
    const Result<PeImage> result = parsePe(file);
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error().code, ErrorCode::MalformedData);
}

TEST(MalformedHeaders, FileEndsInsideOptionalHeader) {
    std::vector<std::byte> file = sampleBuilder().build();
    file.resize(PeBuilder::kOptionalHeaderOffset + 50);
    const Result<PeImage> result = parsePe(file);
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error().code, ErrorCode::MalformedData);
}

TEST(MalformedHeaders, LfanewBeyondFile) {
    std::vector<std::byte> file = sampleBuilder().build();
    writeLe32(file, 0x3C, 0xFFFFFFF0);
    const Result<PeImage> result = parsePe(file);
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error().code, ErrorCode::MalformedData);
}

TEST(MalformedHeaders, MissingPeSignature) {
    std::vector<std::byte> file = sampleBuilder().build();
    writeLe32(file, PeBuilder::kPeHeaderOffset, 0x00004E45);
    const Result<PeImage> result = parsePe(file);
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error().code, ErrorCode::ParserFailure);
}

TEST(MalformedHeaders, TruncatedDataDirectoriesAreNotReportedAbsent) {
    const PeBuilder builder = sampleBuilder();
    std::vector<std::byte> file = builder.build();
    file.resize(builder.dataDirectoryOffset(3) + 4);

    const Result<PeImage> result = parsePe(file);
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
    const PeImage& image = result.value();

    EXPECT_EQ(image.dataDirectories.size(), 3U);
    EXPECT_TRUE(hasIssue(image, "header.data_directories_truncated"));
    EXPECT_TRUE(hasIssue(image, "header.section_table_outside_file"));
    EXPECT_EQ(image.sectionTable.state, FieldState::Invalid);
    EXPECT_EQ(image.certificate.status.state, FieldState::Invalid);
    EXPECT_EQ(image.debug.status.state, FieldState::Invalid);
    EXPECT_EQ(image.overlay.status.state, FieldState::NotInspected);
}

TEST(MalformedHeaders, SectionCountExceedsTable) {
    std::vector<std::byte> file = sampleBuilder().build();
    writeLe16(file, kNumberOfSectionsField, 0xFFFF);
    const Result<PeImage> result = parsePe(file);
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(result.value().sectionTable.state, FieldState::Invalid);
    EXPECT_TRUE(hasIssue(result.value(), "header.section_table_outside_file"));
}

TEST(MalformedHeaders, UnknownOptionalHeaderMagic) {
    std::vector<std::byte> file = sampleBuilder().build();
    writeLe16(file, PeBuilder::kOptionalHeaderOffset, 0x1234);
    const Result<PeImage> result = parsePe(file);
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(result.value().format, PeFormat::Pe32);
    EXPECT_EQ(result.value().optional.magic, 0x1234);
    EXPECT_TRUE(hasIssue(result.value(), "header.optional_magic"));
}

TEST(MalformedHeaders, InconsistentHeaderSizes) {
    std::vector<std::byte> file = sampleBuilder().build();
    writeLe32(file, kSizeOfHeadersField, 0x01000000);
    writeLe32(file, kFileAlignmentField, 3);
    const Result<PeImage> result = parsePe(file);
    ASSERT_TRUE(result.hasValue());
    EXPECT_TRUE(hasIssue(result.value(), "header.size_of_headers_outside_file"));
    EXPECT_TRUE(hasIssue(result.value(), "header.file_alignment"));
}

TEST(MalformedHeaders, EntryPointLocation) {
    const struct {
        std::uint32_t entry;
        std::uint16_t characteristics;
        std::string_view expected;
    } cases[] = {
        {0x9000, 0x0102, "header.entry_point_outside_sections"},
        {0x0010, 0x0102, "header.entry_point_in_headers"},
        {0x0000, 0x0102, "header.entry_point_zero"},
    };
    for (const auto& c : cases) {
        std::vector<std::byte> file = sampleBuilder().build();
        writeLe32(file, kEntryPointField, c.entry);
        writeLe16(file, kCharacteristicsField, c.characteristics);
        const Result<PeImage> result = parsePe(file);
        ASSERT_TRUE(result.hasValue());
        EXPECT_TRUE(hasIssue(result.value(), c.expected)) << c.expected;
    }
}

TEST(MalformedHeaders, DllWithoutEntryPointIsNormal) {
    std::vector<std::byte> file = sampleBuilder().build();
    writeLe32(file, kEntryPointField, 0);
    writeLe16(file, kCharacteristicsField, 0x2102);
    const Result<PeImage> result = parsePe(file);
    ASSERT_TRUE(result.hasValue());
    EXPECT_TRUE(result.value().issues.empty());
}

TEST(MalformedHeaders, DataDirectoryOutsideImage) {
    const PeBuilder builder = sampleBuilder();
    std::vector<std::byte> file = builder.build();
    writeLe32(file, builder.dataDirectoryOffset(pe::kResourceDirectory), 0x7FFF0000);
    writeLe32(file, builder.dataDirectoryOffset(pe::kResourceDirectory) + 4, 0x100);

    const Result<PeImage> result = parsePe(file);
    ASSERT_TRUE(result.hasValue());
    EXPECT_TRUE(hasIssue(result.value(), "header.data_directory_outside_image"));
    EXPECT_EQ(result.value().resources.status.state, FieldState::ParserError);
}

TEST(MalformedHeaders, CertificateTablePastEndOfFile) {
    const PeBuilder builder = sampleBuilder();
    std::vector<std::byte> file = builder.build();
    writeLe32(file, builder.dataDirectoryOffset(pe::kCertificateDirectory), 0x400);
    writeLe32(file, builder.dataDirectoryOffset(pe::kCertificateDirectory) + 4, 0x10000);

    const Result<PeImage> result = parsePe(file);
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(result.value().certificate.status.state, FieldState::Invalid);
    EXPECT_TRUE(hasIssue(result.value(), "header.certificate_table"));
}

TEST(MalformedHeaders, FewerDataDirectoriesThanUsual) {
    std::vector<std::byte> file = sampleBuilder().build();
    writeLe32(file, kNumberOfRvaAndSizesField, 2);
    const Result<PeImage> result = parsePe(file);
    ASSERT_TRUE(result.hasValue());
    const PeImage& image = result.value();
    EXPECT_EQ(image.dataDirectories.size(), 2U);
    EXPECT_EQ(image.imports.status.state, FieldState::Present);
    EXPECT_EQ(image.certificate.status.state, FieldState::Absent);
    EXPECT_TRUE(image.issues.empty());
}

TEST(MalformedHeaders, TooManyDataDirectories) {
    std::vector<std::byte> file = sampleBuilder().build();
    writeLe32(file, kNumberOfRvaAndSizesField, 0x100);
    const Result<PeImage> result = parsePe(file);
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(result.value().dataDirectories.size(), 16U);
    EXPECT_TRUE(hasIssue(result.value(), "header.data_directory_count"));
}

TEST(MalformedHeaders, SectionRangesAreKeptVerbatim) {
    const PeBuilder builder = sampleBuilder();
    std::vector<std::byte> file = builder.build();
    // Raw data far past the end of the file, with an end offset that overflows 32 bits.
    writeLe32(file, builder.sectionHeaderOffset(1) + 16, 0x200);
    writeLe32(file, builder.sectionHeaderOffset(1) + 20, 0xFFFFFF00);

    const Result<PeImage> result = parsePe(file);
    ASSERT_TRUE(result.hasValue());
    ASSERT_GE(result.value().sections.size(), 2U);
    EXPECT_EQ(result.value().sections[1].pointerToRawData, 0xFFFFFF00U);
    EXPECT_EQ(result.value().sections[1].sizeOfRawData, 0x200U);
    EXPECT_EQ(result.value().overlay.status.state, FieldState::Absent);
}

// Random single-byte and dword corruptions of a valid file. The parser may accept or reject
// each input, but it must always return.
TEST(MalformedHeaders, SurvivesHeaderCorruption) {
    const std::vector<std::byte> original = sampleBuilder().build();
    std::mt19937 generator(20261013);
    std::uniform_int_distribution<std::size_t> position(0, 0x3FF);
    std::uniform_int_distribution<std::uint32_t> value;

    for (int i = 0; i < 500; ++i) {
        std::vector<std::byte> file = original;
        const std::size_t offset = position(generator) & ~std::size_t{3};
        writeLe32(file, offset, value(generator));
        const Result<PeImage> result = parsePe(file);
        if (!result) {
            EXPECT_NE(result.error().code, ErrorCode::Internal);
        }
    }
}

} // namespace
} // namespace sectoryn
