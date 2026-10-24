#include "parsers/LiefPeParser.hpp"
#include "parsers/PeConstants.hpp"
#include "support/PeBuilder.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

namespace sectoryn {
namespace {

using test::bytesOf;
using test::PeBuilder;

Result<PeImage> parsePe(const std::vector<std::byte>& file, const AnalysisLimits& limits = {}) {
    return LiefPeParser{}.parse(file, limits, {});
}

std::vector<std::string> issueCodes(const PeImage& image) {
    std::vector<std::string> codes;
    for (const StructuralIssue& issue : image.issues) {
        codes.push_back(issue.code);
    }
    return codes;
}

PeBuilder twoSectionImage(PeFormat format) {
    PeBuilder builder(format);
    builder.timeDateStamp(0x5F5E1000)
        .addSection(".text", PeBuilder::kCode, bytesOf(std::string(0x300, '\xCC')))
        .addSection(".data", PeBuilder::kReadWrite, bytesOf("hello"));
    return builder;
}

TEST(PeHeaders, ParsesPe32) {
    const Result<PeImage> result = parsePe(twoSectionImage(PeFormat::Pe32).build());
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
    const PeImage& image = result.value();

    EXPECT_EQ(image.format, PeFormat::Pe32);
    EXPECT_EQ(image.dos.magic, pe::kDosMagic);
    EXPECT_EQ(image.dos.peHeaderOffset, PeBuilder::kPeHeaderOffset);

    EXPECT_EQ(image.coff.machine, 0x014C);
    EXPECT_EQ(image.coff.numberOfSections, 2);
    EXPECT_EQ(image.coff.timeDateStamp, 0x5F5E1000U);
    EXPECT_EQ(image.coff.sizeOfOptionalHeader, 224);

    EXPECT_EQ(image.optional.magic, pe::kPe32Magic);
    EXPECT_EQ(image.optional.baseOfData, 0U);
    EXPECT_EQ(image.optional.imageBase, 0x400000U);
    EXPECT_EQ(image.optional.sectionAlignment, PeBuilder::kSectionAlignment);
    EXPECT_EQ(image.optional.fileAlignment, PeBuilder::kFileAlignment);
    EXPECT_EQ(image.optional.addressOfEntryPoint, 0x1000U);
    EXPECT_EQ(image.optional.baseOfCode, 0x1000U);
    EXPECT_EQ(image.optional.sizeOfHeaders, 0x200U);
    EXPECT_EQ(image.optional.sizeOfImage, 0x3000U);
    EXPECT_EQ(image.optional.subsystem, 3);
    EXPECT_EQ(image.optional.numberOfRvaAndSizes, 16U);
    EXPECT_EQ(image.dataDirectories.size(), 16U);

    EXPECT_TRUE(image.issues.empty()) << ::testing::PrintToString(issueCodes(image));
}

TEST(PeHeaders, ParsesPe32Plus) {
    const Result<PeImage> result = parsePe(twoSectionImage(PeFormat::Pe32Plus).build());
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
    const PeImage& image = result.value();

    EXPECT_EQ(image.format, PeFormat::Pe32Plus);
    EXPECT_EQ(image.coff.machine, 0x8664);
    EXPECT_EQ(image.coff.sizeOfOptionalHeader, 240);
    EXPECT_EQ(image.optional.magic, pe::kPe32PlusMagic);
    EXPECT_FALSE(image.optional.baseOfData.has_value());
    EXPECT_EQ(image.optional.imageBase, 0x140000000ULL);
    EXPECT_EQ(image.optional.sizeOfStackReserve, 0x100000U);
    EXPECT_EQ(image.dataDirectories.size(), 16U);
    EXPECT_TRUE(image.issues.empty()) << ::testing::PrintToString(issueCodes(image));
}

TEST(PeHeaders, ParsesSectionTable) {
    const Result<PeImage> result = parsePe(twoSectionImage(PeFormat::Pe32).build());
    ASSERT_TRUE(result.hasValue());
    const PeImage& image = result.value();

    EXPECT_EQ(image.sectionTable.state, FieldState::Present);
    ASSERT_EQ(image.sections.size(), 2U);

    const Section& text = image.sections[0];
    EXPECT_EQ(text.name, ".text");
    EXPECT_EQ(text.virtualAddress, 0x1000U);
    EXPECT_EQ(text.virtualSize, 0x300U);
    EXPECT_EQ(text.pointerToRawData, 0x200U);
    EXPECT_EQ(text.sizeOfRawData, 0x400U);
    EXPECT_EQ(text.characteristics, PeBuilder::kCode);

    const Section& data = image.sections[1];
    EXPECT_EQ(data.name, ".data");
    EXPECT_EQ(data.virtualAddress, 0x2000U);
    EXPECT_EQ(data.virtualSize, 5U);
    EXPECT_EQ(data.pointerToRawData, 0x600U);
    EXPECT_EQ(data.sizeOfRawData, 0x200U);
}

TEST(PeHeaders, EscapesSectionNames) {
    const auto file = PeBuilder()
                          .addSection(std::string("a\x01\\b\0\0", 6), PeBuilder::kCode,
                                      bytesOf("x"))
                          .addSection(".textbss", PeBuilder::kCode, bytesOf("y"))
                          .build();
    const Result<PeImage> result = parsePe(file);
    ASSERT_TRUE(result.hasValue());
    ASSERT_EQ(result.value().sections.size(), 2U);

    const Section& odd = result.value().sections[0];
    EXPECT_EQ(odd.name, "a\\x01\\x5cb");
    EXPECT_EQ(odd.rawName[1], 0x01);
    EXPECT_EQ(result.value().sections[1].name, ".textbss");
}

TEST(PeHeaders, OptionalStructuresAreConfirmedAbsent) {
    const Result<PeImage> result = parsePe(twoSectionImage(PeFormat::Pe32).build());
    ASSERT_TRUE(result.hasValue());
    const PeImage& image = result.value();

    for (const FieldStatus* status :
         {&image.imports.status, &image.imports.delayStatus, &image.exports.status,
          &image.resources.status, &image.debug.status, &image.tls.status,
          &image.certificate.status, &image.overlay.status}) {
        EXPECT_EQ(status->state, FieldState::Absent) << status->detail;
    }
}

TEST(PeHeaders, LimitsSectionCount) {
    AnalysisLimits limits;
    limits.maxSections = 1;
    const Result<PeImage> result = parsePe(twoSectionImage(PeFormat::Pe32).build(), limits);
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(result.value().sections.size(), 1U);
    EXPECT_EQ(result.value().sectionTable.state, FieldState::Incomplete);
}

TEST(PeHeaders, DetectsOverlay) {
    PeBuilder builder = twoSectionImage(PeFormat::Pe32);
    const auto file = builder.overlay(bytesOf(std::string(100, 'O'))).build();
    const Result<PeImage> result = parsePe(file);
    ASSERT_TRUE(result.hasValue());

    const Overlay& overlay = result.value().overlay;
    EXPECT_EQ(overlay.status.state, FieldState::Present);
    EXPECT_EQ(overlay.fileOffset, 0x800U);
    EXPECT_EQ(overlay.size, 100U);
    EXPECT_FALSE(overlay.containsCertificateTable);
}

TEST(PeHeaders, LocatesCertificateTableInOverlay) {
    PeBuilder builder = twoSectionImage(PeFormat::Pe32);
    auto file = builder.overlay(bytesOf(std::string(0x100, '\0'))).build();
    test::writeLe32(file, builder.dataDirectoryOffset(pe::kCertificateDirectory), 0x800);
    test::writeLe32(file, builder.dataDirectoryOffset(pe::kCertificateDirectory) + 4, 0x100);

    const Result<PeImage> result = parsePe(file);
    ASSERT_TRUE(result.hasValue());
    const PeImage& image = result.value();
    EXPECT_EQ(image.certificate.status.state, FieldState::Present);
    EXPECT_EQ(image.certificate.fileOffset, 0x800U);
    EXPECT_EQ(image.certificate.size, 0x100U);
    EXPECT_TRUE(image.overlay.containsCertificateTable);
    // The certificate RVA field is a file offset, so it must not be checked against SizeOfImage.
    EXPECT_TRUE(image.issues.empty()) << ::testing::PrintToString(issueCodes(image));
}

TEST(PeHeaders, HonorsCancellation) {
    CancellationSource source;
    source.request_stop();
    const Result<PeImage> result =
        LiefPeParser{}.parse(twoSectionImage(PeFormat::Pe32).build(), {}, source.get_token());
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error().code, ErrorCode::Cancelled);
}

TEST(PeHeaders, EnforcesInputSizeLimit) {
    AnalysisLimits limits;
    limits.maxFileBytes = 0x100;
    const Result<PeImage> result = parsePe(twoSectionImage(PeFormat::Pe32).build(), limits);
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error().code, ErrorCode::ResourceLimitExceeded);
}

TEST(PeHeaders, ReportsParserIdentity) {
    const LiefPeParser parser;
    EXPECT_EQ(parser.name(), "LIEF");
    EXPECT_EQ(parser.version(), "0.17.6");
}

TEST(PeConstants, NamesKnownValues) {
    EXPECT_EQ(pe::machineName(0x8664), "x64 (AMD64)");
    EXPECT_EQ(pe::machineName(0x1234), "unknown");
    EXPECT_EQ(pe::subsystemName(2), "Windows GUI");
    EXPECT_EQ(pe::dataDirectoryName(pe::kCertificateDirectory), "Certificate table");
    EXPECT_EQ(pe::dataDirectoryName(16), "unknown");
    EXPECT_EQ(pe::debugTypeName(2), "CodeView");
}

TEST(PeConstants, DecodesFlags) {
    const std::vector<std::string> flags = pe::decodeFlags(0x2102, pe::coffCharacteristicFlags());
    EXPECT_EQ(flags, (std::vector<std::string>{"EXECUTABLE_IMAGE", "32BIT_MACHINE", "DLL"}));

    // 0x0040 is reserved in the COFF characteristics.
    EXPECT_EQ(pe::decodeFlags(0x0041, pe::coffCharacteristicFlags()),
              (std::vector<std::string>{"RELOCS_STRIPPED", "0x40"}));
    EXPECT_TRUE(pe::decodeFlags(0, pe::dllCharacteristicFlags()).empty());
}

TEST(PeConstants, EscapesNonPrintableText) {
    EXPECT_EQ(pe::escapeNonPrintable(std::string_view(".text\0\0\0", 8)), ".text");
    EXPECT_EQ(pe::escapeNonPrintable(std::string_view("a\0b", 3)), "a\\x00b");
    EXPECT_EQ(pe::escapeNonPrintable("<script>\n"), "<script>\\x0a");
    EXPECT_EQ(pe::escapeNonPrintable("\xFF\\"), "\\xff\\x5c");
}

} // namespace
} // namespace sectoryn
