#include "parsers/PeValidator.hpp"

#include "core/CheckedMath.hpp"
#include "parsers/PeConstants.hpp"

#include <algorithm>
#include <bit>
#include <format>
#include <string>
#include <utility>

namespace sectoryn {

namespace {

constexpr std::uint32_t kMinFileAlignment = 512;
constexpr std::uint32_t kMaxFileAlignment = 64 * 1024;
constexpr std::uint64_t kImageBaseGranularity = 64 * 1024;

void report(PeImage& image, std::string code, std::string message) {
    image.issues.push_back({std::move(code), std::move(message)});
}

std::uint64_t sectionTableEnd(const PeImage& image) {
    return std::uint64_t{image.dos.peHeaderOffset} + pe::kPeSignatureSize + pe::kCoffHeaderSize +
           image.coff.sizeOfOptionalHeader +
           std::uint64_t{image.coff.numberOfSections} * pe::kSectionHeaderSize;
}

// Some linkers leave VirtualSize at zero, in which case the loader uses SizeOfRawData.
std::uint64_t mappedSize(const Section& section) {
    return section.virtualSize != 0 ? section.virtualSize : section.sizeOfRawData;
}

void checkMagic(PeImage& image) {
    if (image.dos.magic != pe::kDosMagic) {
        report(image, "header.dos_magic",
               std::format("DOS header magic is {:#06x} instead of MZ", image.dos.magic));
    }
    const std::uint16_t magic = image.optional.magic;
    if (magic != pe::kPe32Magic && magic != pe::kPe32PlusMagic) {
        report(image, "header.optional_magic",
               std::format("optional header magic {:#06x} is neither PE32 nor PE32+; the format "
                           "was inferred from SizeOfOptionalHeader",
                           magic));
    }
}

void checkHeaderSizes(PeImage& image) {
    const std::uint32_t fixedSize = image.format == PeFormat::Pe32Plus
                                        ? pe::kPe32PlusOptionalHeaderFixedSize
                                        : pe::kPe32OptionalHeaderFixedSize;
    const std::uint64_t neededOptional =
        fixedSize + std::uint64_t{std::min<std::uint32_t>(image.optional.numberOfRvaAndSizes,
                                                          pe::kDataDirectoryCount)} *
                        pe::kDataDirectoryEntrySize;
    if (image.coff.sizeOfOptionalHeader < neededOptional) {
        report(image, "header.optional_header_size",
               std::format("SizeOfOptionalHeader ({}) is smaller than the {} bytes needed for "
                           "the declared data directories",
                           image.coff.sizeOfOptionalHeader, neededOptional));
    }

    if (image.optional.numberOfRvaAndSizes > pe::kDataDirectoryCount) {
        report(image, "header.data_directory_count",
               std::format("NumberOfRvaAndSizes is {}; only {} are defined",
                           image.optional.numberOfRvaAndSizes,
                           static_cast<std::uint32_t>(pe::kDataDirectoryCount)));
    }
    const std::uint32_t declaredDirectories =
        std::min<std::uint32_t>(image.optional.numberOfRvaAndSizes, pe::kDataDirectoryCount);
    if (image.dataDirectories.size() < declaredDirectories) {
        report(image, "header.data_directories_truncated",
               std::format("only {} of {} data directory entries are inside the file",
                           image.dataDirectories.size(), declaredDirectories));
    }

    const std::uint64_t tableEnd = sectionTableEnd(image);
    if (tableEnd > image.fileSize) {
        report(image, "header.section_table_outside_file",
               std::format("the section table ends at {:#x}, past the end of the file ({} bytes)",
                           tableEnd, image.fileSize));
    }
    if (image.optional.sizeOfHeaders > image.fileSize) {
        report(image, "header.size_of_headers_outside_file",
               std::format("SizeOfHeaders ({:#x}) is larger than the file ({} bytes)",
                           image.optional.sizeOfHeaders, image.fileSize));
    }
    if (image.optional.sizeOfHeaders < tableEnd) {
        report(image, "header.size_of_headers_too_small",
               std::format("SizeOfHeaders ({:#x}) does not cover the section table, which ends "
                           "at {:#x}",
                           image.optional.sizeOfHeaders, tableEnd));
    }
}

void checkAlignment(PeImage& image) {
    const std::uint32_t fileAlignment = image.optional.fileAlignment;
    const std::uint32_t sectionAlignment = image.optional.sectionAlignment;

    if (!std::has_single_bit(fileAlignment) || fileAlignment < kMinFileAlignment ||
        fileAlignment > kMaxFileAlignment) {
        report(image, "header.file_alignment",
               std::format("FileAlignment {:#x} is not a power of two between {:#x} and {:#x}",
                           fileAlignment, kMinFileAlignment, kMaxFileAlignment));
    }
    if (!std::has_single_bit(sectionAlignment) || sectionAlignment < fileAlignment) {
        report(image, "header.section_alignment",
               std::format("SectionAlignment {:#x} is not a power of two at least as large as "
                           "FileAlignment ({:#x})",
                           sectionAlignment, fileAlignment));
    }
    if (image.optional.imageBase % kImageBaseGranularity != 0) {
        report(image, "header.image_base_alignment",
               std::format("ImageBase {:#x} is not a multiple of 64 KiB",
                           image.optional.imageBase));
    }
}

void checkImageLayout(PeImage& image) {
    std::uint64_t mappedEnd = image.optional.sizeOfHeaders;
    for (const Section& section : image.sections) {
        mappedEnd =
            std::max(mappedEnd, std::uint64_t{section.virtualAddress} + mappedSize(section));
    }
    if (mappedEnd > image.optional.sizeOfImage) {
        report(image, "header.size_of_image",
               std::format("SizeOfImage ({:#x}) is smaller than the mapped sections, which end at "
                           "{:#x}",
                           image.optional.sizeOfImage, mappedEnd));
    }

    for (const DataDirectory& directory : image.dataDirectories) {
        if (directory.isEmpty() || directory.index == pe::kCertificateDirectory) {
            continue;
        }
        if (!rangeFits(directory.rva, directory.size, image.optional.sizeOfImage)) {
            report(image, "header.data_directory_outside_image",
                   std::format("{} at RVA {:#x}+{:#x} lies outside SizeOfImage ({:#x})",
                               pe::dataDirectoryName(directory.index), directory.rva,
                               directory.size, image.optional.sizeOfImage));
        }
    }

    if (image.certificate.status.state == FieldState::Invalid) {
        report(image, "header.certificate_table", image.certificate.status.detail);
    }
}

void checkEntryPoint(PeImage& image) {
    const std::uint32_t entry = image.optional.addressOfEntryPoint;
    if (entry == 0) {
        // DLLs without an initialization routine legitimately have no entry point.
        if ((image.coff.characteristics & pe::kFileDll) == 0) {
            report(image, "header.entry_point_zero",
                   "AddressOfEntryPoint is 0 in an image that is not a DLL");
        }
        return;
    }

    const bool inSection = std::ranges::any_of(image.sections, [entry](const Section& section) {
        return ByteRange{section.virtualAddress, mappedSize(section)}.contains(entry);
    });
    if (inSection) {
        return;
    }
    if (entry < image.optional.sizeOfHeaders) {
        report(image, "header.entry_point_in_headers",
               std::format("AddressOfEntryPoint {:#x} points into the PE headers", entry));
    } else {
        report(image, "header.entry_point_outside_sections",
               std::format("AddressOfEntryPoint {:#x} is not inside any section", entry));
    }
}

} // namespace

void validateHeaders(PeImage& image) {
    checkMagic(image);
    checkHeaderSizes(image);
    checkAlignment(image);
    checkImageLayout(image);
    checkEntryPoint(image);
}

} // namespace sectoryn
