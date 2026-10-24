#include "analysis/SectionAnalyzer.hpp"
#include "analysis/SectionCharacteristics.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

namespace sectoryn {
namespace {

constexpr std::uint32_t kCodeRx = 0x60000020;
constexpr std::uint32_t kDataRw = 0xC0000040;
constexpr std::uint32_t kDataR = 0x40000040;

Section makeSection(std::string name, std::uint32_t va, std::uint32_t vsize, std::uint32_t raw,
                    std::uint32_t rawSize, std::uint32_t characteristics) {
    Section section;
    std::copy_n(name.begin(), std::min<std::size_t>(name.size(), 8), section.rawName.begin());
    section.name = std::move(name);
    section.virtualAddress = va;
    section.virtualSize = vsize;
    section.pointerToRawData = raw;
    section.sizeOfRawData = rawSize;
    section.characteristics = characteristics;
    return section;
}

PeImage makeImage(std::vector<Section> sections, std::uint64_t fileSize = 0x1000) {
    PeImage image;
    image.fileSize = fileSize;
    image.optional.sectionAlignment = 0x1000;
    image.optional.fileAlignment = 0x200;
    image.optional.sizeOfHeaders = 0x200;
    image.optional.sizeOfImage = 0x10000;
    image.sections = std::move(sections);
    return image;
}

bool has(const SectionAnalysis& analysis, std::size_t section, SectionAnomalyKind kind) {
    return std::ranges::any_of(analysis.anomalies, [&](const SectionAnomaly& anomaly) {
        return anomaly.section == section && anomaly.kind == kind;
    });
}

TEST(SectionCharacteristics, DecodesPermissions) {
    const SectionFlags code = decodeSectionFlags(kCodeRx);
    EXPECT_TRUE(code.read);
    EXPECT_FALSE(code.write);
    EXPECT_TRUE(code.execute);
    EXPECT_TRUE(code.containsCode);
    EXPECT_EQ(permissionString(code), "R-X");
    EXPECT_EQ(permissionString(decodeSectionFlags(0xE0000020)), "RWX");
    EXPECT_EQ(permissionString(decodeSectionFlags(0)), "---");
}

TEST(SectionCharacteristics, DecodesAlignment) {
    EXPECT_FALSE(sectionAlignmentOf(kCodeRx).has_value());
    EXPECT_EQ(sectionAlignmentOf(0x00100000), 1U);
    EXPECT_EQ(sectionAlignmentOf(0x00500000), 16U);
    EXPECT_EQ(sectionAlignmentOf(0x00E00000), 8192U);
    EXPECT_FALSE(sectionAlignmentOf(0x00F00000).has_value());
}

TEST(SectionCharacteristics, NamesFlags) {
    EXPECT_EQ(describeSectionCharacteristics(kCodeRx),
              (std::vector<std::string>{"CNT_CODE", "MEM_EXECUTE", "MEM_READ"}));
    EXPECT_EQ(describeSectionCharacteristics(0x00500020),
              (std::vector<std::string>{"CNT_CODE", "ALIGN_16BYTES"}));
    EXPECT_EQ(describeSectionCharacteristics(0x00F00001),
              (std::vector<std::string>{"ALIGN_UNDEFINED(15)", "0x1"}));
}

TEST(SectionAnalyzer, CleanLayoutHasNoAnomalies) {
    const PeImage image = makeImage({
        makeSection(".text", 0x1000, 0x300, 0x200, 0x400, kCodeRx),
        makeSection(".data", 0x2000, 0x10, 0x600, 0x200, kDataRw),
        makeSection(".bss", 0x3000, 0x800, 0, 0, 0xC0000080),
    });
    const SectionAnalysis analysis = analyzeSections(image);
    ASSERT_EQ(analysis.sections.size(), 3U);
    EXPECT_TRUE(analysis.anomalies.empty());

    EXPECT_EQ(analysis.sections[0].availability, SectionDataAvailability::Full);
    EXPECT_EQ(analysis.sections[0].readableRange, (ByteRange{0x200, 0x400}));
    EXPECT_EQ(analysis.sections[2].availability, SectionDataAvailability::None);
    EXPECT_TRUE(analysis.sections[2].readableRange.empty());
}

TEST(SectionAnalyzer, FlagsPermissions) {
    const PeImage image = makeImage({
        makeSection(".rwx", 0x1000, 0x100, 0x200, 0x200, 0xE0000020),
        makeSection(".x", 0x2000, 0x100, 0x400, 0x200, 0x60000040),
        makeSection(".shr", 0x3000, 0x100, 0x600, 0x200, 0xD0000040),
    });
    const SectionAnalysis analysis = analyzeSections(image);
    EXPECT_TRUE(has(analysis, 0, SectionAnomalyKind::WritableAndExecutable));
    EXPECT_FALSE(has(analysis, 0, SectionAnomalyKind::ExecutableWithoutCodeFlag));
    EXPECT_TRUE(has(analysis, 1, SectionAnomalyKind::ExecutableWithoutCodeFlag));
    EXPECT_TRUE(has(analysis, 2, SectionAnomalyKind::SharedAndWritable));
}

TEST(SectionAnalyzer, ClassifiesDataAvailability) {
    const PeImage image = makeImage(
        {
            makeSection(".a", 0x1000, 0x100, 0x200, 0x200, kDataR),
            makeSection(".b", 0x2000, 0x100, 0x400, 0x400, kDataR),
            makeSection(".c", 0x3000, 0x100, 0x5000, 0x200, kDataR),
            makeSection(".d", 0x4000, 0x100, 0xFFFFFE00, 0x400, kDataR),
        },
        0x600);
    const SectionAnalysis analysis = analyzeSections(image);

    EXPECT_EQ(analysis.sections[0].availability, SectionDataAvailability::Full);
    EXPECT_EQ(analysis.sections[1].availability, SectionDataAvailability::Truncated);
    EXPECT_EQ(analysis.sections[1].readableRange, (ByteRange{0x400, 0x200}));
    EXPECT_TRUE(has(analysis, 1, SectionAnomalyKind::RawDataTruncated));
    EXPECT_EQ(analysis.sections[2].availability, SectionDataAvailability::OutsideFile);
    EXPECT_TRUE(analysis.sections[2].readableRange.empty());
    EXPECT_TRUE(has(analysis, 2, SectionAnomalyKind::RawDataOutsideFile));
    // The raw end of .d does not fit in 32 bits; it must still be reported, not wrapped.
    EXPECT_EQ(analysis.sections[3].availability, SectionDataAvailability::OutsideFile);
}

TEST(SectionAnalyzer, DetectsOverlaps) {
    const PeImage image = makeImage({
        makeSection(".a", 0x1000, 0x2000, 0x200, 0x400, kDataR),
        makeSection(".b", 0x2000, 0x100, 0x400, 0x200, kDataR),
    });
    const SectionAnalysis analysis = analyzeSections(image);
    EXPECT_TRUE(has(analysis, 0, SectionAnomalyKind::VirtualRangeOverlap));
    EXPECT_TRUE(has(analysis, 0, SectionAnomalyKind::RawDataOverlap));

    const auto overlap = std::ranges::find_if(analysis.anomalies, [](const SectionAnomaly& a) {
        return a.kind == SectionAnomalyKind::RawDataOverlap;
    });
    ASSERT_NE(overlap, analysis.anomalies.end());
    EXPECT_EQ(overlap->otherSection, 1U);
}

TEST(SectionAnalyzer, DetectsLayoutProblems) {
    const PeImage image = makeImage({
        makeSection(".a", 0x2000, 0x100, 0x100, 0x200, kDataR),
        makeSection(".b", 0x1800, 0x100, 0x410, 0x200, kDataR),
        makeSection(".c", 0xF000, 0x2000, 0x800, 0x200, kDataR),
    });
    const SectionAnalysis analysis = analyzeSections(image);
    EXPECT_TRUE(has(analysis, 0, SectionAnomalyKind::RawDataInHeaders));
    EXPECT_TRUE(has(analysis, 1, SectionAnomalyKind::VirtualAddressOutOfOrder));
    EXPECT_TRUE(has(analysis, 1, SectionAnomalyKind::VirtualAddressMisaligned));
    EXPECT_TRUE(has(analysis, 1, SectionAnomalyKind::RawOffsetMisaligned));
    EXPECT_TRUE(has(analysis, 2, SectionAnomalyKind::BeyondSizeOfImage));
}

TEST(SectionAnalyzer, ChecksNames) {
    Section unnamed = makeSection("", 0x1000, 0x100, 0x200, 0x200, kDataR);
    Section binary = makeSection("", 0x2000, 0x100, 0x400, 0x200, kDataR);
    binary.rawName = {'.', 0x01, 'x', 0, 0, 0, 0, 0};
    binary.name = ".\\x01x";
    const PeImage image = makeImage({
        unnamed,
        binary,
        makeSection("UPX1", 0x3000, 0x100, 0x600, 0x200, kDataR),
    });
    const SectionAnalysis analysis = analyzeSections(image);
    EXPECT_TRUE(has(analysis, 0, SectionAnomalyKind::EmptyName));
    EXPECT_TRUE(has(analysis, 1, SectionAnomalyKind::NonPrintableName));
    EXPECT_TRUE(has(analysis, 2, SectionAnomalyKind::PackerSectionName));
}

TEST(SectionAnalyzer, BoundsAnomalyCount) {
    // Every section overlaps every other one: n*(n-1) pairwise anomalies without a cap.
    std::vector<Section> sections;
    for (int i = 0; i < 100; ++i) {
        sections.push_back(makeSection(".dup", 0x1000, 0x1000, 0x200, 0x200, kDataR));
    }
    const SectionAnalysis analysis = analyzeSections(makeImage(std::move(sections)));
    EXPECT_EQ(analysis.anomalies.size(), SectionAnalysis::kMaxAnomalies);
    EXPECT_TRUE(analysis.anomaliesTruncated);
}

TEST(SectionAnalyzer, EveryKindHasName) {
    for (int i = 0; i <= static_cast<int>(SectionAnomalyKind::PackerSectionName); ++i) {
        EXPECT_NE(toString(static_cast<SectionAnomalyKind>(i)), "unknown");
    }
}

} // namespace
} // namespace sectoryn
