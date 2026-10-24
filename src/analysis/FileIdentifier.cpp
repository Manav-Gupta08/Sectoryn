#include "analysis/FileIdentifier.hpp"

#include "core/ByteOrder.hpp"
#include "core/CheckedMath.hpp"
#include "utilities/FileReader.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <span>
#include <string>
#include <utility>

namespace sectoryn {

namespace {

constexpr std::size_t kPrefixBytes = 64;
constexpr std::size_t kDosHeaderBytes = 0x40;
constexpr std::size_t kLfanewOffset = 0x3C;

// Fat Mach-O and Java class files share the CAFEBABE magic. Fat binaries store a small
// architecture count where class files store a version number of at least 45.
constexpr std::uint32_t kMaxFatArchitectures = 30;

struct Magic {
    FileKind kind;
    std::string_view bytes;
};

constexpr std::array kMagics = {
    Magic{FileKind::Elf, "\x7F"
                         "ELF"},
    Magic{FileKind::MachO, "\xFE\xED\xFA\xCE"},
    Magic{FileKind::MachO, "\xFE\xED\xFA\xCF"},
    Magic{FileKind::MachO, "\xCE\xFA\xED\xFE"},
    Magic{FileKind::MachO, "\xCF\xFA\xED\xFE"},
    Magic{FileKind::Zip, "PK\x03\x04"},
    Magic{FileKind::Zip, "PK\x05\x06"},
    Magic{FileKind::Zip, "PK\x07\x08"},
    Magic{FileKind::Pdf, "%PDF-"},
    Magic{FileKind::Gzip, "\x1F\x8B"},
    Magic{FileKind::SevenZip, "7z\xBC\xAF\x27\x1C"},
    Magic{FileKind::Rar, "Rar!\x1A\x07"},
    Magic{FileKind::OleCompound, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"},
};

bool startsWith(std::span<const std::byte> data, std::string_view magic) {
    const auto sameByte = [](char expected, std::byte actual) {
        return static_cast<unsigned char>(expected) == std::to_integer<unsigned char>(actual);
    };
    return data.size() >= magic.size() &&
           std::equal(magic.begin(), magic.end(), data.begin(), sameByte);
}

FileIdentification notPe(std::string detail) {
    return {FileKind::MzWithoutPe, std::move(detail), std::nullopt};
}

Result<FileIdentification> identifyMz(FileReader& reader, std::span<const std::byte> prefix) {
    if (reader.size() < kDosHeaderBytes) {
        return notPe(std::format("MZ signature present, but the file ({} bytes) is too small for "
                                 "a {}-byte DOS header",
                                 reader.size(), kDosHeaderBytes));
    }

    // The size check above guarantees the prefix covers the whole DOS header.
    const std::uint32_t lfanew = readLe<std::uint32_t>(prefix, kLfanewOffset).value_or(0);
    std::array<std::byte, 4> signature{};
    if (!rangeFits(lfanew, signature.size(), reader.size())) {
        return notPe(std::format("e_lfanew ({:#x}) points outside the file ({} bytes)", lfanew,
                                 reader.size()));
    }
    if (Status status = reader.readExact(lfanew, signature); !status) {
        return std::move(status).error();
    }

    if (startsWith(signature, std::string_view("PE\0\0", 4))) {
        return FileIdentification{FileKind::Pe, std::format("PE signature at {:#x}", lfanew),
                                  lfanew};
    }
    if (startsWith(signature, "NE")) {
        return notPe("16-bit NE executable; only PE files are supported");
    }
    if (startsWith(signature, "LE") || startsWith(signature, "LX")) {
        return notPe("LE/LX executable (VxD or OS/2); only PE files are supported");
    }
    return notPe(std::format("no PE signature at e_lfanew ({:#x}); possibly a DOS program",
                             lfanew));
}

} // namespace

std::string_view toString(FileKind kind) noexcept {
    switch (kind) {
    case FileKind::Unknown:
        return "unknown";
    case FileKind::Pe:
        return "PE";
    case FileKind::MzWithoutPe:
        return "MZ executable without PE header";
    case FileKind::Elf:
        return "ELF";
    case FileKind::MachO:
        return "Mach-O";
    case FileKind::Zip:
        return "ZIP archive";
    case FileKind::Pdf:
        return "PDF document";
    case FileKind::Gzip:
        return "gzip archive";
    case FileKind::SevenZip:
        return "7-Zip archive";
    case FileKind::Rar:
        return "RAR archive";
    case FileKind::OleCompound:
        return "OLE compound document";
    }
    return "unknown";
}

Result<FileIdentification> identifyFile(FileReader& reader) {
    if (reader.size() == 0) {
        return FileIdentification{FileKind::Unknown, "file is empty", std::nullopt};
    }

    std::array<std::byte, kPrefixBytes> buffer{};
    const std::span<std::byte> prefix =
        std::span(buffer).first(static_cast<std::size_t>(std::min<std::uint64_t>(reader.size(),
                                                                                  buffer.size())));
    if (Status status = reader.readExact(0, prefix); !status) {
        return std::move(status).error();
    }

    if (startsWith(prefix, "MZ")) {
        return identifyMz(reader, prefix);
    }

    for (const Magic& magic : kMagics) {
        if (startsWith(prefix, magic.bytes)) {
            return FileIdentification{
                magic.kind,
                std::format("{} signature; only PE files are supported", toString(magic.kind)),
                std::nullopt};
        }
    }

    if (startsWith(prefix, "\xCA\xFE\xBA\xBE") &&
        readBe<std::uint32_t>(prefix, 4).value_or(UINT32_MAX) <= kMaxFatArchitectures) {
        return FileIdentification{FileKind::MachO,
                                  "universal Mach-O signature; only PE files are supported",
                                  std::nullopt};
    }

    return FileIdentification{FileKind::Unknown, "no recognized file signature", std::nullopt};
}

} // namespace sectoryn
