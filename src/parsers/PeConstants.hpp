#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// Numeric constants and display names from the Microsoft PE/COFF specification.

namespace sectoryn::pe {

inline constexpr std::uint16_t kDosMagic = 0x5A4D;
inline constexpr std::uint16_t kPe32Magic = 0x10B;
inline constexpr std::uint16_t kPe32PlusMagic = 0x20B;
inline constexpr std::uint32_t kPeSignatureSize = 4;
inline constexpr std::uint32_t kCoffHeaderSize = 20;
inline constexpr std::uint32_t kSectionHeaderSize = 40;
inline constexpr std::uint32_t kDataDirectoryEntrySize = 8;
// Size of the optional header without its data directories.
inline constexpr std::uint32_t kPe32OptionalHeaderFixedSize = 96;
inline constexpr std::uint32_t kPe32PlusOptionalHeaderFixedSize = 112;

enum DataDirectoryIndex : std::uint32_t {
    kExportDirectory = 0,
    kImportDirectory = 1,
    kResourceDirectory = 2,
    kExceptionDirectory = 3,
    kCertificateDirectory = 4,
    kBaseRelocationDirectory = 5,
    kDebugDirectory = 6,
    kArchitectureDirectory = 7,
    kGlobalPointerDirectory = 8,
    kTlsDirectory = 9,
    kLoadConfigDirectory = 10,
    kBoundImportDirectory = 11,
    kIatDirectory = 12,
    kDelayImportDirectory = 13,
    kClrRuntimeDirectory = 14,
    kReservedDirectory = 15,
    kDataDirectoryCount = 16,
};

inline constexpr std::uint16_t kFileDll = 0x2000;
inline constexpr std::uint32_t kSectionExecute = 0x20000000;
inline constexpr std::uint32_t kSectionRead = 0x40000000;
inline constexpr std::uint32_t kSectionWrite = 0x80000000;

struct FlagName {
    std::uint32_t bit;
    std::string_view name;
};

// The returned names are "unknown" for values the specification does not define.
[[nodiscard]] std::string_view machineName(std::uint16_t machine) noexcept;
[[nodiscard]] std::string_view subsystemName(std::uint16_t subsystem) noexcept;
[[nodiscard]] std::string_view dataDirectoryName(std::uint32_t index) noexcept;
[[nodiscard]] std::string_view debugTypeName(std::uint32_t type) noexcept;

[[nodiscard]] std::span<const FlagName> coffCharacteristicFlags() noexcept;
[[nodiscard]] std::span<const FlagName> dllCharacteristicFlags() noexcept;

// Names of the flags set in `value`. Bits without a name are reported as one hex value.
[[nodiscard]] std::vector<std::string> decodeFlags(std::uint32_t value,
                                                   std::span<const FlagName> flags);

// Makes text from a file safe to show as a single line: printable ASCII is kept and every
// other byte becomes \xNN. Trailing NUL bytes are dropped first.
[[nodiscard]] std::string escapeNonPrintable(std::string_view raw);

} // namespace sectoryn::pe
