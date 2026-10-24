#include "analysis/SectionCharacteristics.hpp"

#include <array>
#include <format>
#include <string_view>

namespace sectoryn {

namespace {

constexpr std::uint32_t kCode = 0x00000020;
constexpr std::uint32_t kInitializedData = 0x00000040;
constexpr std::uint32_t kUninitializedData = 0x00000080;
constexpr std::uint32_t kDiscardable = 0x02000000;
constexpr std::uint32_t kShared = 0x10000000;
constexpr std::uint32_t kExecute = 0x20000000;
constexpr std::uint32_t kRead = 0x40000000;
constexpr std::uint32_t kWrite = 0x80000000;

constexpr std::uint32_t kAlignMask = 0x00F00000;
constexpr unsigned kAlignShift = 20;
// Encodings 1..14 mean 1..8192 bytes; 15 is undefined.
constexpr std::uint32_t kMaxAlignEncoding = 14;

struct Flag {
    std::uint32_t bit;
    std::string_view name;
};

constexpr std::array kFlags = {
    Flag{0x00000008, "TYPE_NO_PAD"},
    Flag{kCode, "CNT_CODE"},
    Flag{kInitializedData, "CNT_INITIALIZED_DATA"},
    Flag{kUninitializedData, "CNT_UNINITIALIZED_DATA"},
    Flag{0x00000100, "LNK_OTHER"},
    Flag{0x00000200, "LNK_INFO"},
    Flag{0x00000800, "LNK_REMOVE"},
    Flag{0x00001000, "LNK_COMDAT"},
    Flag{0x00008000, "GPREL"},
    Flag{0x00020000, "MEM_16BIT"},
    Flag{0x00040000, "MEM_LOCKED"},
    Flag{0x00080000, "MEM_PRELOAD"},
    Flag{0x01000000, "LNK_NRELOC_OVFL"},
    Flag{kDiscardable, "MEM_DISCARDABLE"},
    Flag{0x04000000, "MEM_NOT_CACHED"},
    Flag{0x08000000, "MEM_NOT_PAGED"},
    Flag{kShared, "MEM_SHARED"},
    Flag{kExecute, "MEM_EXECUTE"},
    Flag{kRead, "MEM_READ"},
    Flag{kWrite, "MEM_WRITE"},
};

} // namespace

SectionFlags decodeSectionFlags(std::uint32_t characteristics) noexcept {
    const auto has = [characteristics](std::uint32_t bit) { return (characteristics & bit) != 0; };
    return {
        .read = has(kRead),
        .write = has(kWrite),
        .execute = has(kExecute),
        .shared = has(kShared),
        .discardable = has(kDiscardable),
        .containsCode = has(kCode),
        .containsInitializedData = has(kInitializedData),
        .containsUninitializedData = has(kUninitializedData),
    };
}

std::string permissionString(const SectionFlags& flags) {
    return {flags.read ? 'R' : '-', flags.write ? 'W' : '-', flags.execute ? 'X' : '-'};
}

std::optional<std::uint32_t> sectionAlignmentOf(std::uint32_t characteristics) noexcept {
    const std::uint32_t encoding = (characteristics & kAlignMask) >> kAlignShift;
    if (encoding == 0 || encoding > kMaxAlignEncoding) {
        return std::nullopt;
    }
    return 1U << (encoding - 1);
}

std::vector<std::string> describeSectionCharacteristics(std::uint32_t characteristics) {
    std::vector<std::string> names;
    std::uint32_t known = kAlignMask;
    for (const Flag& flag : kFlags) {
        known |= flag.bit;
        if ((characteristics & flag.bit) != 0) {
            names.emplace_back(flag.name);
        }
    }

    const std::uint32_t encoding = (characteristics & kAlignMask) >> kAlignShift;
    if (const std::optional<std::uint32_t> alignment = sectionAlignmentOf(characteristics)) {
        names.push_back(std::format("ALIGN_{}BYTES", *alignment));
    } else if (encoding != 0) {
        names.push_back(std::format("ALIGN_UNDEFINED({})", encoding));
    }

    if (const std::uint32_t unknown = characteristics & ~known; unknown != 0) {
        names.push_back(std::format("{:#x}", unknown));
    }
    return names;
}

} // namespace sectoryn
