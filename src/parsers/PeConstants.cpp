#include "parsers/PeConstants.hpp"

#include <array>
#include <format>

namespace sectoryn::pe {

namespace {

constexpr std::string_view kUnknown = "unknown";

struct CodeName {
    std::uint32_t code;
    std::string_view name;
};

template <std::size_t N>
std::string_view lookup(const std::array<CodeName, N>& table, std::uint32_t code) noexcept {
    for (const CodeName& entry : table) {
        if (entry.code == code) {
            return entry.name;
        }
    }
    return kUnknown;
}

constexpr std::array kMachines = {
    CodeName{0x0000, "unknown"},
    CodeName{0x014C, "x86 (i386)"},
    CodeName{0x8664, "x64 (AMD64)"},
    CodeName{0x01C0, "ARM little endian"},
    CodeName{0x01C2, "ARM Thumb"},
    CodeName{0x01C4, "ARM Thumb-2 (ARMNT)"},
    CodeName{0xAA64, "ARM64"},
    CodeName{0xA641, "ARM64EC"},
    CodeName{0xA64E, "ARM64X"},
    CodeName{0x0200, "Intel Itanium (IA-64)"},
    CodeName{0x0EBC, "EFI byte code"},
    CodeName{0x0162, "MIPS R3000"},
    CodeName{0x0166, "MIPS R4000"},
    CodeName{0x0168, "MIPS R10000"},
    CodeName{0x0169, "MIPS WCE v2"},
    CodeName{0x0266, "MIPS16"},
    CodeName{0x0366, "MIPS with FPU"},
    CodeName{0x0466, "MIPS16 with FPU"},
    CodeName{0x0184, "Alpha AXP"},
    CodeName{0x0284, "Alpha 64"},
    CodeName{0x01A2, "Hitachi SH3"},
    CodeName{0x01A3, "Hitachi SH3 DSP"},
    CodeName{0x01A6, "Hitachi SH4"},
    CodeName{0x01A8, "Hitachi SH5"},
    CodeName{0x01F0, "PowerPC"},
    CodeName{0x01F1, "PowerPC with FPU"},
    CodeName{0x9041, "Mitsubishi M32R"},
    CodeName{0x5032, "RISC-V 32-bit"},
    CodeName{0x5064, "RISC-V 64-bit"},
    CodeName{0x5128, "RISC-V 128-bit"},
    CodeName{0x6232, "LoongArch 32-bit"},
    CodeName{0x6264, "LoongArch 64-bit"},
};

constexpr std::array kSubsystems = {
    CodeName{0, "unknown"},
    CodeName{1, "native"},
    CodeName{2, "Windows GUI"},
    CodeName{3, "Windows console"},
    CodeName{5, "OS/2 console"},
    CodeName{7, "POSIX console"},
    CodeName{8, "native Windows 9x driver"},
    CodeName{9, "Windows CE GUI"},
    CodeName{10, "EFI application"},
    CodeName{11, "EFI boot service driver"},
    CodeName{12, "EFI runtime driver"},
    CodeName{13, "EFI ROM"},
    CodeName{14, "Xbox"},
    CodeName{16, "Windows boot application"},
};

constexpr std::array<std::string_view, kDataDirectoryCount> kDataDirectories = {
    "Export table",
    "Import table",
    "Resource table",
    "Exception table",
    "Certificate table",
    "Base relocations",
    "Debug",
    "Architecture",
    "Global pointer",
    "TLS table",
    "Load configuration",
    "Bound import",
    "Import address table",
    "Delay import",
    "CLR runtime header",
    "Reserved",
};

constexpr std::array kDebugTypes = {
    CodeName{0, "unknown"},
    CodeName{1, "COFF"},
    CodeName{2, "CodeView"},
    CodeName{3, "FPO"},
    CodeName{4, "Misc"},
    CodeName{5, "Exception"},
    CodeName{6, "Fixup"},
    CodeName{7, "OMAP to source"},
    CodeName{8, "OMAP from source"},
    CodeName{9, "Borland"},
    CodeName{10, "Reserved"},
    CodeName{11, "CLSID"},
    CodeName{12, "VC feature"},
    CodeName{13, "POGO"},
    CodeName{14, "ILTCG"},
    CodeName{15, "MPX"},
    CodeName{16, "Repro"},
    CodeName{17, "Embedded portable PDB"},
    CodeName{19, "PDB checksum"},
    CodeName{20, "Extended DLL characteristics"},
};

constexpr std::array kCoffFlags = {
    FlagName{0x0001, "RELOCS_STRIPPED"},
    FlagName{0x0002, "EXECUTABLE_IMAGE"},
    FlagName{0x0004, "LINE_NUMS_STRIPPED"},
    FlagName{0x0008, "LOCAL_SYMS_STRIPPED"},
    FlagName{0x0010, "AGGRESSIVE_WS_TRIM"},
    FlagName{0x0020, "LARGE_ADDRESS_AWARE"},
    FlagName{0x0080, "BYTES_REVERSED_LO"},
    FlagName{0x0100, "32BIT_MACHINE"},
    FlagName{0x0200, "DEBUG_STRIPPED"},
    FlagName{0x0400, "REMOVABLE_RUN_FROM_SWAP"},
    FlagName{0x0800, "NET_RUN_FROM_SWAP"},
    FlagName{0x1000, "SYSTEM"},
    FlagName{0x2000, "DLL"},
    FlagName{0x4000, "UP_SYSTEM_ONLY"},
    FlagName{0x8000, "BYTES_REVERSED_HI"},
};

constexpr std::array kDllFlags = {
    FlagName{0x0020, "HIGH_ENTROPY_VA"},
    FlagName{0x0040, "DYNAMIC_BASE"},
    FlagName{0x0080, "FORCE_INTEGRITY"},
    FlagName{0x0100, "NX_COMPAT"},
    FlagName{0x0200, "NO_ISOLATION"},
    FlagName{0x0400, "NO_SEH"},
    FlagName{0x0800, "NO_BIND"},
    FlagName{0x1000, "APPCONTAINER"},
    FlagName{0x2000, "WDM_DRIVER"},
    FlagName{0x4000, "GUARD_CF"},
    FlagName{0x8000, "TERMINAL_SERVER_AWARE"},
};

} // namespace

std::string_view machineName(std::uint16_t machine) noexcept {
    return lookup(kMachines, machine);
}

std::string_view subsystemName(std::uint16_t subsystem) noexcept {
    return lookup(kSubsystems, subsystem);
}

std::string_view dataDirectoryName(std::uint32_t index) noexcept {
    return index < kDataDirectories.size() ? kDataDirectories[index] : kUnknown;
}

std::string_view debugTypeName(std::uint32_t type) noexcept {
    return lookup(kDebugTypes, type);
}

std::span<const FlagName> coffCharacteristicFlags() noexcept {
    return kCoffFlags;
}

std::span<const FlagName> dllCharacteristicFlags() noexcept {
    return kDllFlags;
}

std::vector<std::string> decodeFlags(std::uint32_t value, std::span<const FlagName> flags) {
    std::vector<std::string> names;
    std::uint32_t known = 0;
    for (const FlagName& flag : flags) {
        known |= flag.bit;
        if ((value & flag.bit) != 0) {
            names.emplace_back(flag.name);
        }
    }
    if (const std::uint32_t unknown = value & ~known; unknown != 0) {
        names.push_back(std::format("{:#x}", unknown));
    }
    return names;
}

std::string escapeNonPrintable(std::string_view raw) {
    while (!raw.empty() && raw.back() == '\0') {
        raw.remove_suffix(1);
    }

    std::string text;
    text.reserve(raw.size());
    for (const char c : raw) {
        const auto byte = static_cast<unsigned char>(c);
        if (byte >= 0x20 && byte < 0x7F && c != '\\') {
            text.push_back(c);
        } else {
            text += std::format("\\x{:02x}", byte);
        }
    }
    return text;
}

} // namespace sectoryn::pe
