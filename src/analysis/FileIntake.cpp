#include "analysis/FileIntake.hpp"

#include <format>
#include <system_error>
#include <utility>

namespace sectoryn {

namespace {

std::optional<std::chrono::system_clock::time_point>
lastWriteTimeOf(const std::filesystem::path& path) {
    std::error_code ec;
    const std::filesystem::file_time_type time = std::filesystem::last_write_time(path, ec);
    if (ec) {
        return std::nullopt;
    }
    return std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        std::chrono::clock_cast<std::chrono::system_clock>(time));
}

} // namespace

Result<OpenedFile> openForAnalysis(const std::filesystem::path& path,
                                   const AnalysisLimits& limits) {
    Result<FileReader> opened = FileReader::open(path);
    if (!opened) {
        return std::move(opened).error();
    }
    FileReader reader = std::move(opened).value();

    if (reader.size() == 0) {
        return Error{ErrorCode::InvalidInput, "file is empty"};
    }
    if (reader.size() > limits.maxFileBytes) {
        return Error{ErrorCode::ResourceLimitExceeded,
                     std::format("file is {} bytes; the configured limit is {} bytes",
                                 reader.size(), limits.maxFileBytes)};
    }

    FileMetadata metadata{
        .path = path,
        .sizeBytes = reader.size(),
        .lastWriteTime = lastWriteTimeOf(path),
    };
    return OpenedFile{std::move(metadata), std::move(reader)};
}

} // namespace sectoryn
