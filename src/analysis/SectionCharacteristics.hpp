#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sectoryn {

struct SectionFlags {
    bool read = false;
    bool write = false;
    bool execute = false;
    bool shared = false;
    bool discardable = false;
    bool containsCode = false;
    bool containsInitializedData = false;
    bool containsUninitializedData = false;
};

[[nodiscard]] SectionFlags decodeSectionFlags(std::uint32_t characteristics) noexcept;

// "RWX" style summary, with '-' for a missing permission.
[[nodiscard]] std::string permissionString(const SectionFlags& flags);

// Alignment encoded in bits 20-23. Only meaningful in object files; images ignore it.
[[nodiscard]] std::optional<std::uint32_t>
sectionAlignmentOf(std::uint32_t characteristics) noexcept;

// Names of every set flag, e.g. "MEM_EXECUTE" or "ALIGN_16BYTES"; undefined bits as one hex value.
[[nodiscard]] std::vector<std::string>
describeSectionCharacteristics(std::uint32_t characteristics);

} // namespace sectoryn
