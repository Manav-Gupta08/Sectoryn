#include "parsers/OverlayInfo.hpp"
#include "parsers/PeConstants.hpp"

#include <gtest/gtest.h>

namespace sectoryn {
namespace {

PeImage imageWithSections(std::uint64_t fileSize) {
    PeImage image;
    image.fileSize = fileSize;
    image.optional.numberOfRvaAndSizes = pe::kDataDirectoryCount;
    image.optional.sizeOfHeaders = 0x400;
    for (std::uint32_t i = 0; i < pe::kDataDirectoryCount; ++i) {
        image.dataDirectories.push_back({i, 0, 0});
    }
    image.sectionTable = FieldStatus::present();

    Section text;
    text.pointerToRawData = 0x400;
    text.sizeOfRawData = 0x1000;
    Section bss;
    bss.pointerToRawData = 0;
    bss.sizeOfRawData = 0;
    Section data;
    data.pointerToRawData = 0x1400;
    data.sizeOfRawData = 0x200;
    image.sections = {text, bss, data};
    return image;
}

void setCertificate(PeImage& image, std::uint32_t offset, std::uint32_t size) {
    image.dataDirectories[pe::kCertificateDirectory] = {pe::kCertificateDirectory, offset, size};
}

TEST(Overlay, AbsentWhenFileEndsWithLastSection) {
    PeImage image = imageWithSections(0x1600);
    describeCertificateTable(image);
    describeOverlay(image);
    EXPECT_EQ(image.overlay.status.state, FieldState::Absent);
    EXPECT_EQ(image.certificate.status.state, FieldState::Absent);
}

TEST(Overlay, PresentAfterLastSection) {
    PeImage image = imageWithSections(0x1700);
    describeCertificateTable(image);
    describeOverlay(image);
    EXPECT_EQ(image.overlay.status.state, FieldState::Present);
    EXPECT_EQ(image.overlay.fileOffset, 0x1600U);
    EXPECT_EQ(image.overlay.size, 0x100U);
    EXPECT_FALSE(image.overlay.containsCertificateTable);
}

TEST(Overlay, UsesFurthestSectionNotLastInTable) {
    PeImage image = imageWithSections(0x3000);
    image.sections[0].sizeOfRawData = 0x2000;
    describeOverlay(image);
    EXPECT_EQ(image.overlay.fileOffset, 0x2400U);
    EXPECT_EQ(image.overlay.size, 0xC00U);
}

TEST(Overlay, HeadersOnlyImage) {
    PeImage image = imageWithSections(0x500);
    image.sections.clear();
    image.sectionTable = FieldStatus::absent("NumberOfSections is 0");
    describeOverlay(image);
    EXPECT_EQ(image.overlay.status.state, FieldState::Present);
    EXPECT_EQ(image.overlay.fileOffset, 0x400U);
}

TEST(Overlay, UnknownWhenSectionTableUnreadable) {
    PeImage image = imageWithSections(0x5000);
    image.sectionTable = FieldStatus::invalid("truncated");
    describeOverlay(image);
    EXPECT_EQ(image.overlay.status.state, FieldState::NotInspected);
}

TEST(Overlay, SectionsPastEndOfFileMeanNoOverlay) {
    PeImage image = imageWithSections(0x1000);
    describeOverlay(image);
    EXPECT_EQ(image.overlay.status.state, FieldState::Absent);
}

TEST(CertificateTable, InsideOverlay) {
    PeImage image = imageWithSections(0x2000);
    setCertificate(image, 0x1800, 0x800);
    describeCertificateTable(image);
    describeOverlay(image);
    EXPECT_EQ(image.certificate.status.state, FieldState::Present);
    EXPECT_TRUE(image.overlay.containsCertificateTable);
}

TEST(CertificateTable, RejectsInconsistentEntries) {
    for (const auto& [offset, size] : {std::pair<std::uint32_t, std::uint32_t>{0, 0x100},
                                       {0x1800, 0},
                                       {0x1800, 0x900},
                                       {0xFFFFFFF0, 0x20}}) {
        PeImage image = imageWithSections(0x2000);
        setCertificate(image, offset, size);
        describeCertificateTable(image);
        EXPECT_EQ(image.certificate.status.state, FieldState::Invalid)
            << std::hex << offset << "+" << size;
    }
}

TEST(CertificateTable, MissingDirectoryEntryIsNotConfirmedAbsence) {
    PeImage image = imageWithSections(0x2000);
    image.dataDirectories.resize(3);
    describeCertificateTable(image);
    EXPECT_EQ(image.certificate.status.state, FieldState::Invalid);

    image.optional.numberOfRvaAndSizes = 3;
    describeCertificateTable(image);
    EXPECT_EQ(image.certificate.status.state, FieldState::Absent);
}

} // namespace
} // namespace sectoryn
