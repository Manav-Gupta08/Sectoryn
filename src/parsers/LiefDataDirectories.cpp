#include "parsers/LiefDetail.hpp"
#include "parsers/PeConstants.hpp"

#include <LIEF/PE/Binary.hpp>
#include <LIEF/PE/DataDirectory.hpp>

#include <algorithm>

namespace sectoryn::lief_detail {

void extractDataDirectories(const LIEF::PE::Binary& binary, PeImage& image) {
    // LIEF always reads 16 entries. The loader only honors NumberOfRvaAndSizes of them, so
    // anything past that count is not a data directory, whatever bytes happen to be there.
    const std::uint32_t declared =
        std::min<std::uint32_t>(image.optional.numberOfRvaAndSizes, pe::kDataDirectoryCount);

    // Entries past the end of the file come back from LIEF as zeros, which would look like a
    // confirmed absence. Only entries that are actually in the file are kept.
    const std::uint64_t tableOffset =
        std::uint64_t{image.dos.peHeaderOffset} + pe::kPeSignatureSize + pe::kCoffHeaderSize +
        (image.format == PeFormat::Pe32Plus ? pe::kPe32PlusOptionalHeaderFixedSize
                                            : pe::kPe32OptionalHeaderFixedSize);
    const std::uint64_t inFile = tableOffset < image.fileSize
                                     ? (image.fileSize - tableOffset) / pe::kDataDirectoryEntrySize
                                     : 0;
    const auto readable = static_cast<std::uint32_t>(std::min<std::uint64_t>(declared, inFile));

    image.dataDirectories.clear();
    image.dataDirectories.reserve(readable);
    std::uint32_t index = 0;
    for (const LIEF::PE::DataDirectory& directory : binary.data_directories()) {
        if (index == readable) {
            break;
        }
        image.dataDirectories.push_back({index, directory.RVA(), directory.size()});
        ++index;
    }
}

} // namespace sectoryn::lief_detail
