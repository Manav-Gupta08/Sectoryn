#include "parsers/OverlayInfo.hpp"

#include "core/CheckedMath.hpp"
#include "parsers/PeConstants.hpp"

#include <algorithm>
#include <format>

namespace sectoryn {

void describeCertificateTable(PeImage& image) {
    CertificateTable& table = image.certificate;
    const DataDirectory* directory = image.declaredDirectory(pe::kCertificateDirectory);
    if (directory == nullptr) {
        table = {image.directoryAbsence(pe::kCertificateDirectory), 0, 0};
        return;
    }

    // Unlike every other data directory, this entry holds a file offset rather than an RVA.
    table.fileOffset = directory->rva;
    table.size = directory->size;
    if (table.fileOffset == 0 || table.size == 0) {
        table.status = FieldStatus::invalid(std::format(
            "certificate table entry has offset {:#x} and size {:#x}", table.fileOffset,
            table.size));
    } else if (!rangeFits(table.fileOffset, table.size, image.fileSize)) {
        table.status = FieldStatus::invalid(std::format(
            "certificate table at {:#x}+{:#x} extends past the end of the file ({} bytes)",
            table.fileOffset, table.size, image.fileSize));
    } else {
        table.status = FieldStatus::present();
    }
}

void describeOverlay(PeImage& image) {
    Overlay& overlay = image.overlay;
    overlay = {};

    if (!image.sectionTable.hasData() && image.sectionTable.state != FieldState::Absent) {
        overlay.status = {FieldState::NotInspected,
                          "the section table could not be read, so the end of the image data "
                          "is unknown"};
        return;
    }

    // Declared sizes are used as-is. The loader also rounds PointerToRawData down to 512
    // bytes, which can only move section data earlier, never later.
    std::uint64_t imageEnd = image.optional.sizeOfHeaders;
    for (const Section& section : image.sections) {
        if (section.sizeOfRawData == 0) {
            continue;
        }
        imageEnd = std::max<std::uint64_t>(imageEnd, std::uint64_t{section.pointerToRawData} +
                                                         section.sizeOfRawData);
    }

    if (imageEnd >= image.fileSize) {
        overlay.status = FieldStatus::absent("no data follows the last section");
        return;
    }

    overlay.fileOffset = imageEnd;
    overlay.size = image.fileSize - imageEnd;
    overlay.status = FieldStatus::present();

    // A present certificate table lies within the file, and the overlay runs to its end.
    if (image.certificate.status.state == FieldState::Present) {
        overlay.containsCertificateTable =
            ByteRange{overlay.fileOffset, overlay.size}.contains(image.certificate.fileOffset);
    }
}

} // namespace sectoryn
