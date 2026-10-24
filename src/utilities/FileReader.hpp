#pragma once

#include "core/CancellationToken.hpp"
#include "core/CheckedMath.hpp"
#include "core/Result.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <span>

namespace sectoryn {

// Read-only access to a file whose contents are untrusted. Every read is checked against the
// file size captured at open time, so a bad offset fails cleanly instead of reading garbage.
// Not thread-safe; give each job its own reader.
class FileReader {
public:
    using ChunkHandler = std::function<Status(std::span<const std::byte>)>;

    // Directories, devices and pipes are rejected before anything is opened.
    [[nodiscard]] static Result<FileReader> open(const std::filesystem::path& path);

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }
    [[nodiscard]] std::uint64_t size() const noexcept { return size_; }

    // Fills the whole buffer from `offset`, or fails if that range lies outside the file.
    [[nodiscard]] Status readExact(std::uint64_t offset, std::span<std::byte> buffer);

    // Streams `range` in pieces of at most `chunkBytes`, checking for cancellation before each.
    [[nodiscard]] Status forEachChunk(ByteRange range, std::size_t chunkBytes,
                                      const CancellationToken& token,
                                      const ChunkHandler& handler);

private:
    FileReader(std::filesystem::path path, std::ifstream stream, std::uint64_t size);

    std::filesystem::path path_;
    std::ifstream stream_;
    std::uint64_t size_ = 0;
};

} // namespace sectoryn
