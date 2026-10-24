#pragma once

#include "core/Result.hpp"

#include <cstddef>
#include <cstdint>

namespace sectoryn {

inline constexpr std::uint64_t kMiB = 1024ULL * 1024ULL;

// Resource limits applied to a single analysis job. Defaults favour typical desktop use;
// every value can be overridden through Config.
struct AnalysisLimits {
    std::uint64_t maxFileBytes = 256 * kMiB;
    std::size_t readChunkBytes = 64 * 1024;

    // The PE format allows up to 65535 sections, but the Windows loader rejects more than 96.
    std::size_t maxSections = 96;
    std::size_t maxImportedModules = 1024;
    std::size_t maxImportedFunctions = 65536;
    std::size_t maxExports = 65536;
    std::size_t maxResourceEntries = 4096;

    std::size_t maxStrings = 100000;
    std::size_t maxStringBytes = 16 * kMiB;
    std::size_t minStringLength = 5;
    std::size_t maxStringLength = 4096;

    friend bool operator==(const AnalysisLimits&, const AnalysisLimits&) = default;
};

// Hard ceilings for user-supplied limits; anything above these is treated as a mistake.
struct LimitCeilings {
    static constexpr std::uint64_t maxFileBytes = 4096 * kMiB;
    static constexpr std::size_t minReadChunkBytes = 4096;
    static constexpr std::size_t maxReadChunkBytes = 16 * 1024 * 1024;
    static constexpr std::size_t maxSections = 65535;
    static constexpr std::size_t maxImportedModules = 65536;
    static constexpr std::size_t maxImportedFunctions = 1048576;
    static constexpr std::size_t maxExports = 1048576;
    static constexpr std::size_t maxResourceEntries = 1048576;
    static constexpr std::size_t maxStrings = 10000000;
    static constexpr std::size_t maxStringBytes = 1024 * kMiB;
    static constexpr std::size_t maxStringLength = 65536;
};

[[nodiscard]] Status validate(const AnalysisLimits& limits);

} // namespace sectoryn
