#include "parsers/LiefPeParser.hpp"

#include "core/ByteOrder.hpp"
#include "core/CheckedMath.hpp"
#include "parsers/LiefDetail.hpp"
#include "parsers/OverlayInfo.hpp"
#include "parsers/PeConstants.hpp"
#include "parsers/PeValidator.hpp"

#include <LIEF/PE/Binary.hpp>
#include <LIEF/PE/DosHeader.hpp>
#include <LIEF/PE/Header.hpp>
#include <LIEF/PE/Parser.hpp>
#include <LIEF/PE/ParserConfig.hpp>
#include <LIEF/version.h>

#include <cstdint>
#include <exception>
#include <format>
#include <memory>
#include <new>
#include <optional>

namespace sectoryn {

namespace {

LIEF::PE::ParserConfig parserConfig() {
    LIEF::PE::ParserConfig config;
    // Signatures are verified by the platform adapter; parsing the PKCS#7 blob here would only
    // expose another hostile-input parser. Relocations and exception data are not used.
    config.parse_signature = false;
    config.parse_reloc = false;
    config.parse_exceptions = false;
    config.parse_arm64x_binary = false;
    return config;
}

// LIEF reports a header that runs past the end of the data only as a log message and still
// returns a Binary full of zeros. The fixed-size headers are therefore checked up front.
Status checkFixedHeaders(std::span<const std::byte> data) {
    constexpr std::size_t kLfanewOffset = 0x3C;
    constexpr std::size_t kSizeOfOptionalHeaderOffset = 16;
    constexpr std::uint16_t kPe32PlusOptionalHeaderSize = 0xF0;

    const std::optional<std::uint32_t> lfanew = readLe<std::uint32_t>(data, kLfanewOffset);
    if (!lfanew) {
        return Error{ErrorCode::MalformedData, "file ends inside the DOS header"};
    }
    const std::uint64_t coffOffset = std::uint64_t{*lfanew} + pe::kPeSignatureSize;
    const std::uint64_t optionalOffset = coffOffset + pe::kCoffHeaderSize;
    if (!rangeFits(coffOffset, pe::kCoffHeaderSize + sizeof(std::uint16_t), data.size())) {
        return Error{ErrorCode::MalformedData, "file ends inside the COFF file header"};
    }

    // Same rule LIEF uses: trust the magic, otherwise fall back to SizeOfOptionalHeader.
    const auto at = static_cast<std::size_t>(coffOffset);
    const std::uint16_t magic = readLe<std::uint16_t>(data, at + pe::kCoffHeaderSize).value_or(0);
    const std::uint16_t optionalSize =
        readLe<std::uint16_t>(data, at + kSizeOfOptionalHeaderOffset).value_or(0);
    const bool pe32Plus = magic == pe::kPe32PlusMagic ||
                          (magic != pe::kPe32Magic && optionalSize == kPe32PlusOptionalHeaderSize);
    const std::uint32_t fixedSize =
        pe32Plus ? pe::kPe32PlusOptionalHeaderFixedSize : pe::kPe32OptionalHeaderFixedSize;
    if (!rangeFits(optionalOffset, fixedSize, data.size())) {
        return Error{ErrorCode::MalformedData, "file ends inside the optional header"};
    }
    return {};
}

void extractDosHeader(const LIEF::PE::Binary& binary, PeImage& image) {
    const LIEF::PE::DosHeader& dos = binary.dos_header();
    image.dos = {
        .magic = dos.magic(),
        .bytesOnLastPage = dos.used_bytes_in_last_page(),
        .pagesInFile = dos.file_size_in_pages(),
        .relocations = dos.numberof_relocation(),
        .headerParagraphs = dos.header_size_in_paragraphs(),
        .minExtraParagraphs = dos.minimum_extra_paragraphs(),
        .maxExtraParagraphs = dos.maximum_extra_paragraphs(),
        .initialSs = dos.initial_relative_ss(),
        .initialSp = dos.initial_sp(),
        .checksum = dos.checksum(),
        .initialIp = dos.initial_ip(),
        .initialCs = dos.initial_relative_cs(),
        .relocationTableOffset = dos.addressof_relocation_table(),
        .overlayNumber = dos.overlay_number(),
        .oemId = dos.oem_id(),
        .oemInfo = dos.oem_info(),
        .peHeaderOffset = dos.addressof_new_exeheader(),
    };
}

void extractCoffHeader(const LIEF::PE::Binary& binary, PeImage& image) {
    const LIEF::PE::Header& header = binary.header();
    image.coff = {
        .machine = static_cast<std::uint16_t>(header.machine()),
        .numberOfSections = header.numberof_sections(),
        .timeDateStamp = header.time_date_stamp(),
        .pointerToSymbolTable = header.pointerto_symbol_table(),
        .numberOfSymbols = header.numberof_symbols(),
        .sizeOfOptionalHeader = header.sizeof_optional_header(),
        .characteristics = static_cast<std::uint16_t>(header.characteristics()),
    };
}

Status buildImage(const LIEF::PE::Binary& binary, const AnalysisLimits& limits,
                  const CancellationToken& token, PeImage& image) {
    extractDosHeader(binary, image);
    extractCoffHeader(binary, image);
    lief_detail::extractOptionalHeader(binary, image);
    lief_detail::extractDataDirectories(binary, image);
    lief_detail::extractSections(binary, limits, image);

    if (Status status = checkCancelled(token); !status) {
        return status;
    }
    lief_detail::extractImports(binary, limits, image);
    lief_detail::extractExports(binary, limits, image);

    if (Status status = checkCancelled(token); !status) {
        return status;
    }
    lief_detail::extractResources(binary, limits, image);
    lief_detail::extractDebug(binary, image);
    lief_detail::extractTls(binary, image);

    describeCertificateTable(image);
    describeOverlay(image);
    validateHeaders(image);
    return {};
}

} // namespace

Result<PeImage> LiefPeParser::parse(std::span<const std::byte> data, const AnalysisLimits& limits,
                                    const CancellationToken& token) const {
    if (Status status = checkCancelled(token); !status) {
        return std::move(status).error();
    }
    if (data.size() > limits.maxFileBytes) {
        return Error{ErrorCode::ResourceLimitExceeded,
                     std::format("input is {} bytes; the configured limit is {} bytes",
                                 data.size(), limits.maxFileBytes)};
    }
    if (Status status = checkFixedHeaders(data); !status) {
        return std::move(status).error();
    }

    // LIEF reads through a span over `data` and copies what it keeps, so `binary` does not
    // reference the caller's buffer after parsing.
    try {
        const std::unique_ptr<LIEF::PE::Binary> binary = LIEF::PE::Parser::parse(
            reinterpret_cast<const std::uint8_t*>(data.data()), data.size(), parserConfig());
        if (!binary) {
            return Error{ErrorCode::ParserFailure, "LIEF could not read the PE headers"};
        }

        PeImage image;
        image.fileSize = data.size();
        if (Status status = buildImage(*binary, limits, token, image); !status) {
            return std::move(status).error();
        }
        return image;
    } catch (const std::bad_alloc&) {
        return Error{ErrorCode::ResourceLimitExceeded, "out of memory while parsing"};
    } catch (const std::exception& e) {
        return Error{ErrorCode::ParserFailure, std::format("parser raised: {}", e.what())};
    }
}

std::string LiefPeParser::name() const {
    return "LIEF";
}

std::string LiefPeParser::version() const {
    return std::format("{}.{}.{}", LIEF_VERSION_MAJOR, LIEF_VERSION_MINOR, LIEF_VERSION_PATCH);
}

} // namespace sectoryn
