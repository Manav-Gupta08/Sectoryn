#pragma once

#include "analysis/SectionCharacteristics.hpp"
#include "core/CheckedMath.hpp"
#include "parsers/PeModel.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sectoryn {

enum class SectionDataAvailability : std::uint8_t {
    // SizeOfRawData is zero; the loader fills the section with zeros.
    None,
    Full,
    // The raw range starts inside the file but runs past its end.
    Truncated,
    // The raw range starts at or beyond the end of the file.
    OutsideFile,
};

[[nodiscard]] std::string_view toString(SectionDataAvailability availability) noexcept;

// Structural facts about sections. They are evidence for detection rules to weigh, not
// findings by themselves: plenty of legitimate software triggers some of them.
enum class SectionAnomalyKind : std::uint8_t {
    WritableAndExecutable,
    ExecutableWithoutCodeFlag,
    SharedAndWritable,
    RawDataOutsideFile,
    RawDataTruncated,
    RawDataInHeaders,
    RawDataOverlap,
    VirtualRangeOverlap,
    VirtualAddressOutOfOrder,
    VirtualAddressMisaligned,
    RawOffsetMisaligned,
    BeyondSizeOfImage,
    EmptyName,
    NonPrintableName,
    PackerSectionName,
};

[[nodiscard]] std::string_view toString(SectionAnomalyKind kind) noexcept;

struct SectionAnomaly {
    SectionAnomalyKind kind;
    std::size_t section;
    // Set for anomalies that involve a second section, such as overlaps.
    std::optional<std::size_t> otherSection;
    std::string description;
};

struct SectionAssessment {
    SectionFlags flags;
    SectionDataAvailability availability = SectionDataAvailability::None;
    // The part of the declared raw range that actually exists in the file.
    ByteRange readableRange;
};

struct SectionAnalysis {
    // Parallel to PeImage::sections.
    std::vector<SectionAssessment> sections;
    std::vector<SectionAnomaly> anomalies;
    // Set when the anomaly list was cut short at kMaxAnomalies.
    bool anomaliesTruncated = false;

    // Pairwise checks can produce one anomaly per section pair; this keeps the list bounded.
    static constexpr std::size_t kMaxAnomalies = 1000;
};

[[nodiscard]] SectionAnalysis analyzeSections(const PeImage& image);

} // namespace sectoryn
