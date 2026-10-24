#pragma once

#include "core/Limits.hpp"
#include "core/Result.hpp"
#include "utilities/FileReader.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>

namespace sectoryn {

struct FileMetadata {
    std::filesystem::path path;
    std::uint64_t sizeBytes = 0;
    std::optional<std::chrono::system_clock::time_point> lastWriteTime;
};

struct OpenedFile {
    FileMetadata metadata;
    FileReader reader;
};

// Opens a file for analysis. It must be a non-empty regular file no larger than
// limits.maxFileBytes. The size is taken from the opened handle, not from a separate stat.
[[nodiscard]] Result<OpenedFile> openForAnalysis(const std::filesystem::path& path,
                                                 const AnalysisLimits& limits);

} // namespace sectoryn
