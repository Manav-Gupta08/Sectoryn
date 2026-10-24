#pragma once

#include "core/Result.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace sectoryn {

class FileReader;

enum class FileKind : std::uint8_t {
    Unknown,
    Pe,
    MzWithoutPe,
    Elf,
    MachO,
    Zip,
    Pdf,
    Gzip,
    SevenZip,
    Rar,
    OleCompound,
};

[[nodiscard]] std::string_view toString(FileKind kind) noexcept;

struct FileIdentification {
    FileKind kind = FileKind::Unknown;
    // Why the file was classified this way, phrased for the analyst.
    std::string detail;
    // Offset of the "PE\0\0" signature; only set when kind is Pe.
    std::optional<std::uint32_t> peHeaderOffset;
};

// Identifies a file by its content, never by its name. Reads only a few bytes.
[[nodiscard]] Result<FileIdentification> identifyFile(FileReader& reader);

} // namespace sectoryn
