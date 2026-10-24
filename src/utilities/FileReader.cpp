#include "utilities/FileReader.hpp"

#include <algorithm>
#include <format>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>

namespace sectoryn {

FileReader::FileReader(std::filesystem::path path, std::ifstream stream, std::uint64_t size)
    : path_(std::move(path))
    , stream_(std::move(stream))
    , size_(size) {}

Result<FileReader> FileReader::open(const std::filesystem::path& path) {
    if (path.empty()) {
        return Error{ErrorCode::InvalidInput, "no file path given"};
    }

    std::error_code ec;
    const std::filesystem::file_status status = std::filesystem::status(path, ec);
    if (status.type() == std::filesystem::file_type::not_found) {
        return Error{ErrorCode::InvalidInput, "file does not exist"};
    }
    if (ec) {
        return Error{ErrorCode::IoFailure, "cannot access file: " + ec.message()};
    }
    if (std::filesystem::is_directory(status)) {
        return Error{ErrorCode::InvalidInput, "path is a directory"};
    }
    // Opening a FIFO or device could block or never reach end of file.
    if (!std::filesystem::is_regular_file(status)) {
        return Error{ErrorCode::InvalidInput, "not a regular file"};
    }

    std::ifstream stream(path, std::ios::in | std::ios::binary);
    if (!stream.is_open()) {
        return Error{ErrorCode::IoFailure, "cannot open file for reading"};
    }

    // Measure the size through the opened handle so it describes the file actually being read,
    // even if the path was replaced after the status check.
    stream.seekg(0, std::ios::end);
    const std::streamoff end = stream.tellg();
    stream.seekg(0, std::ios::beg);
    if (end < 0 || !stream) {
        return Error{ErrorCode::IoFailure, "cannot determine file size"};
    }

    return FileReader(path, std::move(stream), static_cast<std::uint64_t>(end));
}

Status FileReader::readExact(std::uint64_t offset, std::span<std::byte> buffer) {
    if (!rangeFits(offset, buffer.size(), size_)) {
        return Error{ErrorCode::MalformedData,
                     std::format("read of {} bytes at offset {:#x} is outside the file ({} bytes)",
                                 buffer.size(), offset, size_)};
    }
    if (buffer.empty()) {
        return {};
    }

    const std::optional<std::streamoff> position = checkedCast<std::streamoff>(offset);
    const std::optional<std::streamsize> count = checkedCast<std::streamsize>(buffer.size());
    if (!position || !count) {
        return Error{ErrorCode::ResourceLimitExceeded, "read range exceeds stream limits"};
    }

    stream_.clear();
    stream_.seekg(*position, std::ios::beg);
    stream_.read(reinterpret_cast<char*>(buffer.data()), *count);
    const bool complete = stream_.gcount() == *count;
    stream_.clear();
    if (!complete) {
        return Error{ErrorCode::IoFailure, "short read; the file may have changed during analysis"};
    }
    return {};
}

Status FileReader::forEachChunk(ByteRange range, std::size_t chunkBytes,
                                const CancellationToken& token, const ChunkHandler& handler) {
    if (chunkBytes == 0) {
        return Error{ErrorCode::InvalidInput, "chunk size must be greater than zero"};
    }
    if (!range.fitsWithin(size_)) {
        return Error{ErrorCode::MalformedData,
                     std::format("range {:#x}+{:#x} is outside the file ({} bytes)", range.offset,
                                 range.size, size_)};
    }

    const auto bufferBytes =
        static_cast<std::size_t>(std::min<std::uint64_t>(range.size, chunkBytes));
    std::vector<std::byte> buffer(bufferBytes);

    std::uint64_t position = range.offset;
    std::uint64_t remaining = range.size;
    while (remaining > 0) {
        if (Status status = checkCancelled(token); !status) {
            return status;
        }

        const auto count =
            static_cast<std::size_t>(std::min<std::uint64_t>(remaining, bufferBytes));
        const std::span<std::byte> chunk = std::span(buffer).first(count);
        if (Status status = readExact(position, chunk); !status) {
            return status;
        }
        if (Status status = handler(chunk); !status) {
            return status;
        }

        position += count;
        remaining -= count;
    }
    return {};
}

} // namespace sectoryn
