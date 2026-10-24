#include "parsers/LiefDetail.hpp"
#include "parsers/PeConstants.hpp"

#include <LIEF/PE/Binary.hpp>
#include <LIEF/PE/Section.hpp>

#include <algorithm>
#include <format>
#include <string>
#include <string_view>

namespace sectoryn::lief_detail {

namespace {

// LIEF::PE::Parser stops after this many section headers.
constexpr std::size_t kLiefSectionLimit = 1000;

} // namespace

void extractSections(const LIEF::PE::Binary& binary, const AnalysisLimits& limits,
                     PeImage& image) {
    image.sections.clear();
    const std::size_t declared = image.coff.numberOfSections;
    if (declared == 0) {
        image.sectionTable = FieldStatus::absent("NumberOfSections is 0");
        return;
    }

    const std::size_t wanted = std::min({declared, limits.maxSections, kLiefSectionLimit});
    image.sections.reserve(wanted);
    for (const LIEF::PE::Section& source : binary.sections()) {
        if (image.sections.size() == wanted) {
            break;
        }

        Section section;
        // fullname() is the raw 8-byte field; name() stops at the first NUL.
        const std::string& raw = source.fullname();
        std::copy_n(raw.begin(), std::min(raw.size(), section.rawName.size()),
                    section.rawName.begin());
        section.name = pe::escapeNonPrintable(
            std::string_view(reinterpret_cast<const char*>(section.rawName.data()),
                             section.rawName.size()));
        section.virtualAddress = static_cast<std::uint32_t>(source.virtual_address());
        section.virtualSize = source.virtual_size();
        section.pointerToRawData = source.pointerto_raw_data();
        section.sizeOfRawData = source.sizeof_raw_data();
        section.pointerToRelocations = source.pointerto_relocation();
        section.pointerToLineNumbers = source.pointerto_line_numbers();
        section.numberOfRelocations = source.numberof_relocations();
        section.numberOfLineNumbers = source.numberof_line_numbers();
        section.characteristics = source.characteristics();
        image.sections.push_back(std::move(section));
    }

    if (image.sections.size() < wanted) {
        image.sectionTable = FieldStatus::invalid(
            std::format("NumberOfSections is {}, but only {} section headers could be read",
                        declared, image.sections.size()));
    } else if (wanted < declared) {
        image.sectionTable = FieldStatus::incomplete(
            std::format("NumberOfSections is {}; only the first {} were read", declared, wanted));
    } else {
        image.sectionTable = FieldStatus::present();
    }
}

} // namespace sectoryn::lief_detail
