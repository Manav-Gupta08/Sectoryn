#include "parsers/LiefDetail.hpp"

#include <LIEF/PE/Binary.hpp>
#include <LIEF/PE/OptionalHeader.hpp>

namespace sectoryn::lief_detail {

void extractOptionalHeader(const LIEF::PE::Binary& binary, PeImage& image) {
    const LIEF::PE::OptionalHeader& header = binary.optional_header();
    OptionalHeader& out = image.optional;

    image.format = binary.type() == LIEF::PE::PE_TYPE::PE32_PLUS ? PeFormat::Pe32Plus
                                                                  : PeFormat::Pe32;

    // LIEF keeps the magic as read, even when it had to infer the format from the header size.
    out.magic = static_cast<std::uint16_t>(header.magic());
    out.majorLinkerVersion = header.major_linker_version();
    out.minorLinkerVersion = header.minor_linker_version();
    out.sizeOfCode = header.sizeof_code();
    out.sizeOfInitializedData = header.sizeof_initialized_data();
    out.sizeOfUninitializedData = header.sizeof_uninitialized_data();
    out.addressOfEntryPoint = header.addressof_entrypoint();
    out.baseOfCode = header.baseof_code();
    if (image.format == PeFormat::Pe32) {
        out.baseOfData = header.baseof_data();
    }
    out.imageBase = header.imagebase();
    out.sectionAlignment = header.section_alignment();
    out.fileAlignment = header.file_alignment();
    out.majorOperatingSystemVersion = header.major_operating_system_version();
    out.minorOperatingSystemVersion = header.minor_operating_system_version();
    out.majorImageVersion = header.major_image_version();
    out.minorImageVersion = header.minor_image_version();
    out.majorSubsystemVersion = header.major_subsystem_version();
    out.minorSubsystemVersion = header.minor_subsystem_version();
    out.win32VersionValue = header.win32_version_value();
    out.sizeOfImage = header.sizeof_image();
    out.sizeOfHeaders = header.sizeof_headers();
    out.checksum = header.checksum();
    out.subsystem = static_cast<std::uint16_t>(header.subsystem());
    out.dllCharacteristics = static_cast<std::uint16_t>(header.dll_characteristics());
    out.sizeOfStackReserve = header.sizeof_stack_reserve();
    out.sizeOfStackCommit = header.sizeof_stack_commit();
    out.sizeOfHeapReserve = header.sizeof_heap_reserve();
    out.sizeOfHeapCommit = header.sizeof_heap_commit();
    out.loaderFlags = header.loader_flags();
    out.numberOfRvaAndSizes = header.numberof_rva_and_size();
}

} // namespace sectoryn::lief_detail
