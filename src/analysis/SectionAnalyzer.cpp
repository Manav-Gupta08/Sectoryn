#include "analysis/SectionAnalyzer.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <format>
#include <utility>

namespace sectoryn {

namespace {

// Section names written by well-known packers and protectors. A match says which tool most
// likely produced the layout; it does not say anything about intent.
constexpr std::array<std::string_view, 29> kPackerSectionNames = {
    "UPX0",     "UPX1",     "UPX2",     ".aspack",  ".adata",   ".petite",  ".themida", ".winlice",
    ".vmp0",    ".vmp1",    ".vmp2",    ".MPRESS1", ".MPRESS2", ".nsp0",    ".nsp1",    ".nsp2",
    ".enigma1", ".enigma2", "PEC2",     "PEC2TO",   ".packed",  ".Upack",   ".ByDwing", ".yP",
    ".y0da",    "FSG!",     "kkrunchy", ".perplex", ".mackt",
};

std::uint64_t mappedSize(const Section& section) {
    return section.virtualSize != 0 ? section.virtualSize : section.sizeOfRawData;
}

ByteRange virtualRange(const Section& section) {
    return {section.virtualAddress, mappedSize(section)};
}

ByteRange rawRange(const Section& section) {
    return {section.pointerToRawData, section.sizeOfRawData};
}

bool hasNonPrintableName(const Section& section) {
    auto end = section.rawName.end();
    while (end != section.rawName.begin() && *(end - 1) == 0) {
        --end;
    }
    return std::any_of(section.rawName.begin(), end,
                       [](std::uint8_t byte) { return byte < 0x20 || byte >= 0x7F; });
}

class AnomalyCollector {
public:
    explicit AnomalyCollector(SectionAnalysis& analysis)
        : analysis_(analysis) {}

    void add(SectionAnomalyKind kind, std::size_t section, std::string description,
             std::optional<std::size_t> other = std::nullopt) {
        if (analysis_.anomalies.size() >= SectionAnalysis::kMaxAnomalies) {
            analysis_.anomaliesTruncated = true;
            return;
        }
        analysis_.anomalies.push_back({kind, section, other, std::move(description)});
    }

private:
    SectionAnalysis& analysis_;
};

SectionAssessment assess(const Section& section, std::uint64_t fileSize, std::size_t index,
                         AnomalyCollector& anomalies) {
    SectionAssessment result;
    result.flags = decodeSectionFlags(section.characteristics);
    if (section.sizeOfRawData == 0) {
        result.availability = SectionDataAvailability::None;
        return result;
    }

    const ByteRange raw = rawRange(section);
    if (raw.offset >= fileSize) {
        result.availability = SectionDataAvailability::OutsideFile;
        anomalies.add(SectionAnomalyKind::RawDataOutsideFile, index,
                      std::format("raw data at {:#x} starts beyond the end of the file ({} bytes)",
                                  raw.offset, fileSize));
        return result;
    }

    const std::uint64_t available = std::min(raw.size, fileSize - raw.offset);
    result.readableRange = {raw.offset, available};
    if (available < raw.size) {
        result.availability = SectionDataAvailability::Truncated;
        anomalies.add(SectionAnomalyKind::RawDataTruncated, index,
                      std::format("raw data {:#x}+{:#x} is cut off by the end of the file; only "
                                  "{:#x} bytes are present",
                                  raw.offset, raw.size, available));
    } else {
        result.availability = SectionDataAvailability::Full;
    }
    return result;
}

void checkSection(const PeImage& image, std::size_t index, const SectionFlags& flags,
                  AnomalyCollector& anomalies) {
    const Section& section = image.sections[index];
    const OptionalHeader& header = image.optional;

    if (flags.write && flags.execute) {
        anomalies.add(SectionAnomalyKind::WritableAndExecutable, index,
                      "section is both writable and executable");
    }
    if (flags.execute && !flags.containsCode) {
        anomalies.add(SectionAnomalyKind::ExecutableWithoutCodeFlag, index,
                      "section is executable but not marked as containing code");
    }
    if (flags.shared && flags.write) {
        anomalies.add(SectionAnomalyKind::SharedAndWritable, index,
                      "section is shared between processes and writable");
    }

    if (section.sizeOfRawData != 0 && section.pointerToRawData < header.sizeOfHeaders) {
        anomalies.add(SectionAnomalyKind::RawDataInHeaders, index,
                      std::format("raw data at {:#x} starts inside the headers (SizeOfHeaders "
                                  "{:#x})",
                                  section.pointerToRawData, header.sizeOfHeaders));
    }
    if (std::has_single_bit(header.sectionAlignment) &&
        section.virtualAddress % header.sectionAlignment != 0) {
        anomalies.add(SectionAnomalyKind::VirtualAddressMisaligned, index,
                      std::format("virtual address {:#x} is not a multiple of SectionAlignment "
                                  "({:#x})",
                                  section.virtualAddress, header.sectionAlignment));
    }
    if (section.sizeOfRawData != 0 && std::has_single_bit(header.fileAlignment) &&
        section.pointerToRawData % header.fileAlignment != 0) {
        anomalies.add(SectionAnomalyKind::RawOffsetMisaligned, index,
                      std::format("raw offset {:#x} is not a multiple of FileAlignment ({:#x})",
                                  section.pointerToRawData, header.fileAlignment));
    }

    const ByteRange mapped = virtualRange(section);
    if (!mapped.fitsWithin(header.sizeOfImage)) {
        anomalies.add(SectionAnomalyKind::BeyondSizeOfImage, index,
                      std::format("mapped range {:#x}+{:#x} extends past SizeOfImage ({:#x})",
                                  mapped.offset, mapped.size, header.sizeOfImage));
    }

    if (section.name.empty()) {
        anomalies.add(SectionAnomalyKind::EmptyName, index, "section has no name");
    } else if (hasNonPrintableName(section)) {
        anomalies.add(SectionAnomalyKind::NonPrintableName, index,
                      std::format("section name '{}' contains non-printable bytes", section.name));
    }
    if (std::ranges::find(kPackerSectionNames, section.name) != kPackerSectionNames.end()) {
        anomalies.add(SectionAnomalyKind::PackerSectionName, index,
                      std::format("section name '{}' is used by a known packer or protector",
                                  section.name));
    }
}

void checkPairs(const PeImage& image, AnomalyCollector& anomalies) {
    const std::vector<Section>& sections = image.sections;
    for (std::size_t i = 0; i < sections.size(); ++i) {
        if (i > 0 && sections[i].virtualAddress < sections[i - 1].virtualAddress) {
            anomalies.add(SectionAnomalyKind::VirtualAddressOutOfOrder, i,
                          std::format("virtual address {:#x} is lower than that of the previous "
                                      "section ({:#x})",
                                      sections[i].virtualAddress, sections[i - 1].virtualAddress),
                          i - 1);
        }
        for (std::size_t j = i + 1; j < sections.size(); ++j) {
            if (virtualRange(sections[i]).overlaps(virtualRange(sections[j]))) {
                anomalies.add(SectionAnomalyKind::VirtualRangeOverlap, i,
                              std::format("mapped range overlaps section {} ('{}')", j,
                                          sections[j].name),
                              j);
            }
            if (rawRange(sections[i]).overlaps(rawRange(sections[j]))) {
                anomalies.add(SectionAnomalyKind::RawDataOverlap, i,
                              std::format("raw data overlaps section {} ('{}')", j,
                                          sections[j].name),
                              j);
            }
        }
    }
}

} // namespace

std::string_view toString(SectionDataAvailability availability) noexcept {
    switch (availability) {
    case SectionDataAvailability::None:
        return "no raw data";
    case SectionDataAvailability::Full:
        return "complete";
    case SectionDataAvailability::Truncated:
        return "truncated";
    case SectionDataAvailability::OutsideFile:
        return "outside file";
    }
    return "unknown";
}

std::string_view toString(SectionAnomalyKind kind) noexcept {
    switch (kind) {
    case SectionAnomalyKind::WritableAndExecutable:
        return "writable and executable";
    case SectionAnomalyKind::ExecutableWithoutCodeFlag:
        return "executable without code flag";
    case SectionAnomalyKind::SharedAndWritable:
        return "shared and writable";
    case SectionAnomalyKind::RawDataOutsideFile:
        return "raw data outside file";
    case SectionAnomalyKind::RawDataTruncated:
        return "raw data truncated";
    case SectionAnomalyKind::RawDataInHeaders:
        return "raw data inside headers";
    case SectionAnomalyKind::RawDataOverlap:
        return "overlapping raw data";
    case SectionAnomalyKind::VirtualRangeOverlap:
        return "overlapping virtual ranges";
    case SectionAnomalyKind::VirtualAddressOutOfOrder:
        return "virtual address out of order";
    case SectionAnomalyKind::VirtualAddressMisaligned:
        return "misaligned virtual address";
    case SectionAnomalyKind::RawOffsetMisaligned:
        return "misaligned raw offset";
    case SectionAnomalyKind::BeyondSizeOfImage:
        return "beyond SizeOfImage";
    case SectionAnomalyKind::EmptyName:
        return "empty name";
    case SectionAnomalyKind::NonPrintableName:
        return "non-printable name";
    case SectionAnomalyKind::PackerSectionName:
        return "packer section name";
    }
    return "unknown";
}

SectionAnalysis analyzeSections(const PeImage& image) {
    SectionAnalysis analysis;
    AnomalyCollector anomalies(analysis);

    analysis.sections.reserve(image.sections.size());
    for (std::size_t i = 0; i < image.sections.size(); ++i) {
        analysis.sections.push_back(assess(image.sections[i], image.fileSize, i, anomalies));
        checkSection(image, i, analysis.sections.back().flags, anomalies);
    }
    checkPairs(image, anomalies);
    return analysis;
}

} // namespace sectoryn
